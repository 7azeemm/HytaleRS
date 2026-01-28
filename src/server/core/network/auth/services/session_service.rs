use std::error::Error;
use std::time::Duration;
use jsonwebtoken::jwk::JwkSet;
use log::{error, info};
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use crate::server::core::hytale_server::VERSION;

pub const SESSION_SERVICE_URL: &str = "https://sessions.hytale.com";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct SessionService {
    client: Client,
}

#[derive(Deserialize)]
struct AccountData {
    profiles: Vec<GameProfile>
}

#[derive(Deserialize, Debug, Clone)]
pub struct GameProfile {
    pub uuid: String,
    pub username: String
}

#[derive(Deserialize, Debug)]
pub struct GameSession {
    #[serde(rename = "sessionToken")]
    pub session_token: String,
    #[serde(rename = "identityToken")]
    pub identity_token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String
}

impl SessionService {
    pub fn new() -> Self {
        Self {
            client: ClientBuilder::new()
                .timeout(CONNECT_TIMEOUT)
                .build()
                .expect("Failed to build session service")
        }
    }

    pub async fn fetch_jwks(&self) -> Option<JwkSet> {
        info!("Fetching JWKS...");

        let response = self.client
            .get(format!("{SESSION_SERVICE_URL}/.well-known/jwks.json"))
            .header("Accept", "application/json")
            .header("User-Agent", format!("HytaleServer/{}", VERSION))
            .send().await;

        match response {
            Err(err) => error!("Failed to fetch JWKS: {}", err),
            Ok(resp) if resp.status() != 200 => error!("Failed to fetch JWKS, Http Code {}", resp.status()),
            Ok(resp) => match resp.bytes().await {
                Err(err) => error!("Failed to fetch JWKS: {}", err),
                Ok(bytes) => match serde_json::from_slice::<JwkSet>(&bytes) {
                    Err(err) => error!("Failed to fetch JWKS: {}", err),
                    Ok(jwks) => {
                        if jwks.keys.is_empty() {
                            error!("Service returned no JWKS");
                            return None
                        }

                        info!("Fetched JWKS successfully");
                        return Some(jwks)
                    }
                }
            }
        }
        None
    }

    pub async fn fetch_game_profiles(&self, access_token: &str) -> Option<Vec<GameProfile>> {
        info!("Fetching game profiles...");

        let response = self.client
            .get("https://account-data.hytale.com/my-account/get-profiles")
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", format!("HytaleServer/{}", VERSION))
            .send().await;

        match response {
            Err(err) => error!("Failed to fetch game profiles: {}", err),
            Ok(resp) if resp.status() != 200 => error!("Failed to fetch game profiles, Http Code {}", resp.status()),
            Ok(resp) => match resp.text().await {
                Err(err) => error!("Failed to fetch game profiles: {}", err),
                Ok(txt) => match serde_json::from_str::<AccountData>(&txt) {
                    Err(err) => error!("Failed to fetch game profiles: {}", err),
                    Ok(data) => {
                        if data.profiles.is_empty() {
                            error!("Account does not have any profiles");
                            return None
                        }

                        info!("Fetched {} game profiles successfully", data.profiles.len());
                        return Some(data.profiles)
                    }
                }
            }
        }
        None
    }

    pub async fn create_game_session(&self, access_token: &str, profile_uuid: &str) -> Option<GameSession> {
        info!("Creating Game Session...");

        let response = self.client
            .post(format!("{}/game-session/new", SESSION_SERVICE_URL))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", format!("HytaleServer/{}", VERSION))
            .body(format!(r#"{{"uuid": "{}"}}"#, profile_uuid))
            .send().await;

        match response {
            Err(err) => error!("Failed to create game session: {}", err),
            Ok(resp) if resp.status() != 200 => error!("Failed to create game session, Http Code {}", resp.status()),
            Ok(resp) => match resp.text().await {
                Err(err) => error!("Failed to create game session: {}", err),
                Ok(txt) => match serde_json::from_str::<GameSession>(&txt) {
                    Err(err) => error!("Failed to create game session: {}", err),
                    Ok(session) => {
                        info!("Created game session successfully");
                        return Some(session)
                    }
                }
            }
        }
        None
    }

    pub async fn refresh_game_session(&self, session_token: &str) -> Option<GameSession> {
        info!("Refreshing game session...");

        let response = self.client
            .post(format!("{}/game-session/refresh", SESSION_SERVICE_URL))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {session_token}"))
            .header("User-Agent", format!("HytaleServer/{}", VERSION))
            .send().await;

        match response {
            Err(err) => error!("Failed to refresh game session: {}", err),
            Ok(resp) if resp.status() != 200 => error!("Failed to refresh game session, Http Code {}", resp.status()),
            Ok(resp) => match resp.text().await {
                Err(err) => error!("Failed to refresh game session: {}", err),
                Ok(txt) => match serde_json::from_str::<GameSession>(&txt) {
                    Err(err) => error!("Failed to refresh game session: {}", err),
                    Ok(session) => {
                        info!("Game session refreshed successfully");
                        return Some(session)
                    }
                }
            }
        }
        None
    }
}
