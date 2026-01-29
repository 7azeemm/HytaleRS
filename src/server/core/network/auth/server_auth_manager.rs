use std::str::FromStr;
use std::sync::{Arc};
use ahash::HashMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{error, info};
use once_cell::sync::OnceCell;
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Instant};
use uuid::Uuid;
use crate::server::core::network::auth::credential_store::{CredentialStore, AuthTokens};
use crate::server::core::network::auth::jwt_validator::JWTValidator;
use crate::server::core::network::auth::services::auth_service::AuthService;
use crate::server::core::network::auth::services::session_service::{GameProfile, GameSession, SessionService};

/*
1. Fetch JWKS (Used for player auth, not server auth) (in tokio task without awaiting)
2. Load credentials (tokens), if exists:
3. If tokens are valid, attempt to restore game session:
4. If tokens expired, refresh and save them
5. Fetch game profiles and select one
6. If selected profile is not set, save it (in the credentials file)
7. Create game session
8. Schedule game session refresh (1 Hour)
*/

static SERVER_AUTH_MANAGER: OnceCell<ServerAuthManager> = OnceCell::new();

#[derive(Debug)]
pub struct ServerAuthManager {
    pub session_service: Arc<SessionService>,
    pub auth_service: Arc<AuthService>,
    pub jwt_validator: Arc<JWTValidator>,
    pub credential_store: CredentialStore,
    pub profiles: Mutex<HashMap<String, GameProfile>>,
    pub game_session: Mutex<Option<GameSession>>,
    pub auth_state: RwLock<AuthState>
}

impl ServerAuthManager {
    pub async fn init() {
        let session_service = Arc::new(SessionService::new());

        SERVER_AUTH_MANAGER.set(Self {
            session_service: session_service.clone(),
            auth_service: Arc::new(AuthService::new()),
            jwt_validator: Arc::new(JWTValidator::new(session_service).await),
            credential_store: CredentialStore::new().await,
            profiles: Mutex::new(HashMap::default()),
            game_session: Mutex::new(None),
            auth_state: RwLock::new(AuthState::Uninitialized),
        }).unwrap();

        let instance = Self::get();
        instance.jwt_validator.fetch_jwks();
        instance.credential_store.load().await;
        instance.auth().await;
    }

    async fn auth(&self) {
        self.set_auth_state(AuthState::Authenticating).await;

        if !self.credential_store.has_tokens().await {
            self.set_auth_state(AuthState::Failed(AuthError::NoCredentials)).await;
            info!("No Server credentials found, please run /auth command to authenticate the server.");
            return;
        }

        info!("Attempting to restore game session...");

        let Some(access_token) = self.refresh_auth_tokens().await else {
            self.set_auth_state(AuthState::Failed(AuthError::RefreshFailed)).await;
            return;
        };

        let Some(profiles) = self.session_service.fetch_game_profiles(&access_token).await else {
            self.set_auth_state(AuthState::Failed(AuthError::NetworkError)).await;
            return;
        };

        {
            let mut profiles_lock = self.profiles.lock().await;
            profiles_lock.clear();
            for profile in profiles.iter() {
                profiles_lock.insert(profile.uuid.clone(), profile.clone());
            }
        }

        let profile = self.try_select_profile(profiles).await;
        info!("Selected profile {} ({})", profile.username, profile.uuid);
        self.credential_store.set_profile(profile.uuid.clone()).await;

        let Some(game_session) = self.session_service.create_game_session(&access_token, &profile.uuid).await else {
            self.set_auth_state(AuthState::Failed(AuthError::NetworkError)).await;
            return;
        };

        self.on_new_game_session(game_session).await;
        info!("Server has been authenticated successfully")
    }

    async fn on_new_game_session(&self, game_session: GameSession) {
        schedule_game_session_refresh(&game_session, game_session.session_token.clone());
        *self.game_session.lock().await = Some(game_session);
        self.set_auth_state(AuthState::Authenticated).await;
    }

    async fn refresh_auth_tokens(&self) -> Option<String> {
        let mut lock = self.credential_store.tokens.lock().await;
        let tokens = lock.as_ref()?;

        // Check if token refresh is needed
        if tokens.expires_at > Utc::now() + Duration::seconds(300) {
            return Some(tokens.access_token.clone());
        }

        if self.get_auth_state().await == AuthState::Refreshing {
            error!("The server is already refreshing the tokens, try again later.");
            return None
        }

        self.set_auth_state(AuthState::Refreshing).await;
        info!("Refreshing Auth Tokens...");

        match self.auth_service.refresh_tokens(&tokens.refresh_token).await {
            Err(err) => error!("Failed to refresh auth tokens: {}", err),
            Ok(new_tokens) => {
                let access_token = new_tokens.access_token.clone();
                *lock = Some(new_tokens);
                drop(lock);
                info!("Refreshed Auth Tokens successfully");

                if let Err(err) = self.credential_store.save().await {
                    error!("Failed to save refreshed tokens: {}", err);
                }

                return Some(access_token);
            }
        };
        None
    }

    async fn try_select_profile(&self, profiles: Vec<GameProfile>) -> GameProfile {
        if profiles.len() > 1 {
            let profile = self.credential_store.profile.lock().await;
            if let Some(profile) = profile.as_ref() {
                if let Some(selected_profile) = self.profiles.lock().await.get(profile) {
                    return selected_profile.clone();
                }
            }
            // TODO: select with command
            info!("Found multiple profiles, selecting first one");
        }

        profiles.first().unwrap().clone()
    }

    pub async fn get_auth_state(&self) -> AuthState {
        *self.auth_state.read().await
    }

    async fn set_auth_state(&self, state: AuthState) {
        *self.auth_state.write().await = state;
    }

    pub fn get() -> &'static ServerAuthManager {
        SERVER_AUTH_MANAGER.get().unwrap()
    }
}

fn schedule_game_session_refresh(session: &GameSession, session_token: String) {
    let Some(expiry) = get_effective_expiry(session) else {
        error!("Failed to get game session expiry. Token refresher won't be scheduled");
        return;
    };

    // Refresh 5 minutes before expiry, or in 30 seconds if expiring soon
    let now = Utc::now();
    let refresh_time = match expiry > now + Duration::minutes(5) {
        true => expiry - now - Duration::minutes(5),
        false => Duration::seconds(30)
    };

    let duration = std::time::Duration::from_secs(refresh_time.num_seconds().max(1) as u64);
    info!("Scheduled token refresh in {:?}", duration);

    // Schedule a one-time refresh task
    tokio::spawn(async move {
        sleep(duration).await;
        let manager = ServerAuthManager::get();
        match manager.session_service.refresh_game_session(&session_token).await {
            None => manager.set_auth_state(AuthState::Failed(AuthError::RefreshFailed)).await,
            Some(game_session) => manager.on_new_game_session(game_session).await
        }
    });
}

fn get_effective_expiry(session: &GameSession) -> Option<DateTime<Utc>> {
    let identity_expiry = parse_identity_token_expiry(&session.identity_token);
    let session_expiry = DateTime::parse_from_rfc3339(&session.expires_at)
        .ok().map(|dt| dt.with_timezone(&Utc));

    match (session_expiry, identity_expiry) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn parse_identity_token_expiry(token: &str) -> Option<DateTime<Utc>> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;

    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;

    let exp = json.get("exp")?.as_i64()?;
    Utc.timestamp_opt(exp, 0).single()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Uninitialized,
    Authenticating,
    Authenticated,
    TokenExpiring,
    Refreshing,
    Failed(AuthError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    NoCredentials,
    InvalidToken,
    RefreshFailed,
    NetworkError,
}
