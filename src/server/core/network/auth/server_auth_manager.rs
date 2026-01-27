use std::str::FromStr;
use std::sync::{Arc};
use ahash::HashMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{error, info};
use once_cell::sync::OnceCell;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;
use crate::GLOBAL_SCHEDULER;
use crate::server::core::network::auth::credential_store::{CredentialStore, AuthTokens};
use crate::server::core::network::auth::jwt_validator::JWTValidator;
use crate::server::core::network::auth::services::auth_service::AuthService;
use crate::server::core::network::auth::services::session_service::{GameProfile, GameSession, SessionService};

static SERVER_AUTH_MANAGER: OnceCell<ServerAuthManager> = OnceCell::new();

#[derive(Debug)]
pub struct ServerAuthManager {
    pub session_id: Uuid,
    pub session_service: Arc<SessionService>,
    pub auth_service: Arc<AuthService>,
    pub jwt_validator: Arc<JWTValidator>,
    pub credential_store: CredentialStore,
    pub profiles: Mutex<HashMap<String, GameProfile>>,
    pub game_session: Mutex<Option<GameSession>>
}

impl ServerAuthManager {
    pub async fn init() {
        let session_service = Arc::new(SessionService::new());

        SERVER_AUTH_MANAGER.set(Self {
            session_id: Uuid::new_v4(),
            session_service: session_service.clone(),
            auth_service: Arc::new(AuthService::new()),
            jwt_validator: JWTValidator::new(session_service).await,
            credential_store: CredentialStore::new().await,
            profiles: Mutex::new(HashMap::default()),
            game_session: Mutex::new(None)
        }).unwrap();

        Self::get().auth().await;
    }

    pub async fn auth(&self) {
        if !self.credential_store.has_tokens().await {
            info!("No Server credentials found, please run /auth command to authenticate the server.");
            return;
        }

        info!("Attempting to restore game session...");

        let Some(access_token) = self.refresh_auth_tokens().await else { return };
        let Some(profiles) = self.session_service.fetch_game_profiles(&access_token).await else { return };

        {
            let mut map = self.profiles.lock().await;
            map.clear();
            for profile in profiles.iter() {
                map.insert(profile.uuid.clone(), profile.clone());
            }
        }

        let profile = self.try_select_profile(profiles).await;
        info!("Selected profile {} ({})", profile.username, profile.uuid);

        let Some(game_session) = self.session_service.create_game_session(&access_token, &profile.uuid).await else { return };
        schedule_token_refresh(&game_session);

        *self.game_session.lock().await = Some(game_session);
        self.credential_store.set_profile(profile.uuid.clone()).await;

        info!("The server has been authenticated")
    }

    async fn refresh_auth_tokens(&self) -> Option<String> {
        let mut lock = self.credential_store.tokens.lock().await;
        let tokens = lock.as_ref().unwrap();
        if tokens.expires_at < Utc::now() + Duration::seconds(300) {
            info!("Refreshing Auth Tokens...");
            match self.auth_service.refresh_tokens(&tokens.refresh_token).await {
                Err(err) => error!("Failed to refresh auth tokens: {}", err),
                Ok(new_tokens) => {
                    let access_token = new_tokens.access_token.clone();
                    *lock = Some(new_tokens);
                    info!("Refreshed Auth Tokens successfully");
                    return Some(access_token);
                }
            };
            return None
        }
        Some(tokens.access_token.clone())
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

    pub fn get() -> &'static ServerAuthManager {
        SERVER_AUTH_MANAGER.get().unwrap()
    }
}

fn schedule_token_refresh(session: &GameSession) {
    let _expiry = match get_effective_expiry(session) {
        Some(e) => e,
        None => {
            error!("Failed to get game session expiry. Token refresher won't be scheduled");
            return;
        }
    };

    //TODO: impl refresher
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




/*
1. Load Auth Credentials (Encrypted/Memory)
2. Check if refreshToken is valid, If yes attempt to restore session
3. If expiresAt is null or close to expire (in the next 5mins) refresh tokens using the refreshToken
4. Send Request to Hytale to get accessToken and expiresAt
5. Create SessionServiceClient (used to communicated with Hytale services using the accessToken)
6. Fetch GameProfiles
7. Try to auto select profile
8. Create GameSession (using the GameProfile)
*/

/*
[2026/01/18 18:40:21   INFO] [EncryptedAuthCredentialStore] Loaded encrypted credentials from auth.enc
[2026/01/18 18:40:21   INFO]            [ServerAuthManager] Auth credential store: Encrypted
[2026/01/18 18:40:21   INFO]            [ServerAuthManager] Found stored credentials, attempting to restore session...
[2026/01/18 18:40:21   INFO]            [ServerAuthManager] Refreshing OAuth tokens...
[2026/01/18 18:40:24   INFO]         [SessionServiceClient] Session Service client initialized for: https://sessions.hytale.com
[2026/01/18 18:40:24   INFO]         [SessionServiceClient] Fetching game profiles...
[2026/01/18 18:40:24   INFO]         [SessionServiceClient] Found 1 game profile(s)
[2026/01/18 18:40:24   INFO]            [ServerAuthManager] Auto-selected profile: 7azem (d510c211-ea66-4cc0-a932-e6f8b797fef7)
[2026/01/18 18:40:24   INFO]         [SessionServiceClient] Creating game session...
[2026/01/18 18:40:25   INFO]         [SessionServiceClient] Successfully created game session
[2026/01/18 18:40:25   INFO]            [ServerAuthManager] Token refresh scheduled in 3301 seconds
[2026/01/18 18:40:25   INFO]            [ServerAuthManager] Authentication successful! Mode: OAUTH_STORE
[2026/01/18 18:40:25   INFO]            [ServerAuthManager] Session restored from stored credentials
 */

/*
[2026/01/20 10:04:32   INFO]   [QUICTransport] Received connection from QuicConnectionAddress{connId=} (/[0:0:0:0:0:0:0:1]:61469) to QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:5520)
[2026/01/20 10:04:34   INFO]          [Hytale] Received stream QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0) to QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:5520, streamId=0)
[2026/01/20 10:04:34 FINEST]     [LoginTiming] setTimeout-initial
[2026/01/20 10:04:34   FINE]     [LoginTiming] Registered took 2ms 44us 900ns
[2026/01/20 10:04:34   FINE]     [LoginTiming] Connect took 504ms 597us 900ns
[2026/01/20 10:04:34   INFO]          [Hytale] Starting authenticated flow for 7azem (d510c211-ea66-4cc0-a932-e6f8b797fef7) from QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0)
[2026/01/20 10:04:34   INFO] [SessionServiceClient] Session Service client initialized for: https://sessions.hytale.com
[2026/01/20 10:04:35   INFO] [SessionServiceClient] Successfully fetched JWKS with 1 keys
[2026/01/20 10:04:35   INFO]         [JWTValidator] JWKS loaded with 1 keys
[2026/01/20 10:04:35   INFO]         [JWTValidator] Identity token validated successfully for user null (UUID: d510c211-ea66-4cc0-a932-e6f8b797fef7)
[2026/01/20 10:04:35   INFO]     [HandshakeHandler] Identity token validated for 7azem (UUID: d510c211-ea66-4cc0-a932-e6f8b797fef7, scope: hytale:client) from QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0), requesting auth grant
[2026/01/20 10:04:35 FINEST]          [LoginTiming] setTimeout-auth-grant-timeout took 1sec 64ms 905us
[2026/01/20 10:04:35   INFO] [SessionServiceClient] Requesting authorization grant with identity token, aud='9a5e75a6-689c-4372-9303-11005ec4b7ae'
[2026/01/20 10:04:36   INFO] [SessionServiceClient] Successfully obtained authorization grant
[2026/01/20 10:04:36   INFO]     [HandshakeHandler] Sending AuthGrant to QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0) (with server identity: true)
[2026/01/20 10:04:36 FINEST]          [LoginTiming] setTimeout-auth-token-timeout took 181ms 456us 700ns
[2026/01/20 10:04:36   INFO]     [HandshakeHandler] Received AuthToken from QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0), validating JWT (mTLS cert present: true, server auth grant: true)
[2026/01/20 10:04:36   INFO]      [CertificateUtil] Certificate binding validated successfully
[2026/01/20 10:04:36   INFO]         [JWTValidator] JWT validated successfully for user 7azem (UUID: d510c211-ea66-4cc0-a932-e6f8b797fef7)
[2026/01/20 10:04:36 FINEST]          [LoginTiming] setTimeout-server-token-exchange-timeout took 698ms 199us 500ns
[2026/01/20 10:04:36   INFO] [SessionServiceClient] Exchanging authorization grant for access token
[2026/01/20 10:04:36   INFO] [SessionServiceClient] Successfully obtained access token
[2026/01/20 10:04:36   INFO]     [HandshakeHandler] Sending ServerAuthToken to QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0) (with password challenge: false)
[2026/01/20 10:04:36   INFO]     [HandshakeHandler] Mutual authentication complete for 7azem (d510c211-ea66-4cc0-a932-e6f8b797fef7) from QuicConnectionAddress{connId=751105726e17200d274be5d5aa14471d046d24b1} (/[0:0:0:0:0:0:0:1]:61469, streamId=0)
[2026/01/20 10:04:36   FINE]          [LoginTiming] Authenticated took 172ms 540us 800ns
[2026/01/20 10:04:36   INFO] [PasswordPacketHandler] Connection complete for 7azem (d510c211-ea66-4cc0-a932-e6f8b797fef7), transitioning to setup
 */