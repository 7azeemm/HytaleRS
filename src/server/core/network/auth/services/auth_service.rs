use std::error::Error;
use std::time::Duration;
use chrono::{DateTime, Utc};
use log::{error, info};
use reqwest::{Client, ClientBuilder};
use serde::Deserialize;
use serde_json::{value, Value};
use tokio::sync::Mutex;
use url::form_urlencoded;
use crate::server::core::hytale_server::VERSION;
use crate::server::core::network::auth::credential_store::AuthTokens;

const AUTH_SERVICE_URL: &str = "https://oauth.accounts.hytale.com/oauth2";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct AuthService {
    client: Client,
}

impl AuthService {
    pub fn new() -> Self {
        Self {
            client: ClientBuilder::new()
                .timeout(CONNECT_TIMEOUT)
                .build()
                .expect("Failed to build auth service")
        }
    }

    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<AuthTokens, Box<dyn Error>> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "hytale-server")
            .append_pair("refresh_token", refresh_token)
            .finish();

        let resp = self.client
            .post("https://oauth.accounts.hytale.com/oauth2/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", format!("HytaleServer/{}", VERSION))
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        let txt = resp.text().await?;

        if status != reqwest::StatusCode::OK {
            return Err(format!("HTTP Code {}: {:#?}", status, txt).into())
        }

        let tokens = serde_json::from_str::<TokenResponse>(&txt)?;
        
        Ok(AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Utc::now() + chrono::Duration::seconds(tokens.expires_in as i64),
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) expires_in: i32
}