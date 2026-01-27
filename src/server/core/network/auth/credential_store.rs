use std::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use log::{error, info};
use rand::RngCore;
use tokio::sync::Mutex;
use crate::server::core::hytale_server::HYTALE_SERVER;
use crate::utils::hardware_utils::get_system_uuid;

const ALGORITHM: &str = "AES/GCM/NoPadding";
const SALT: &[u8] = b"HytaleAuthCredentialStore";
const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32; // 256 bits
const IV_LENGTH: usize = 12; // 96 bits for GCM

//TODO: switch from bson to bincode

#[derive(Debug)]
pub struct CredentialStore {
    path: PathBuf,
    encryption_key: [u8; KEY_LENGTH],
    pub(crate) tokens: Mutex<Option<AuthTokens>>,
    pub profile: Mutex<Option<String>>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthTokens {
    #[serde(rename = "AccessToken")]
    pub(crate) access_token: String,
    #[serde(rename = "RefreshToken")]
    pub(crate) refresh_token: String,
    #[serde(rename = "ExpiresAt")]
    pub(crate) expires_at: DateTime<Utc>,
    #[serde(rename = "ProfileUuid")]
    pub(crate) profile_uuid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) expires_at: DateTime<Utc>,
}

impl CredentialStore {
    pub async fn new() -> Self {
        let encryption_key = Self::derive_key().await;
        let path = PathBuf::from(HYTALE_SERVER.config.read().await.auth_credential_store_path.clone());

        let mut store = Self {
            path,
            encryption_key,
            tokens: Mutex::new(None),
            profile: Mutex::new(None)
        };

        store.load().await;
        store
    }

    pub async fn set_profile(&self, profile: String) {
        *self.profile.lock().await = Some(profile);
        if let Err(err) = self.save().await {
            error!("Failed to save server credentials: {err}")
        }
    }

    pub async fn update_tokens(&self, tokens: AuthTokens) {
        *self.tokens.lock().await = Some(tokens);
    }

    pub async fn has_tokens(&self) -> bool {
        self.tokens.lock().await.is_some()
    }

    async fn derive_key() -> [u8; KEY_LENGTH] {
        let start_time = Instant::now();
        let hardware_id = get_system_uuid();
        let mut key = [0u8; KEY_LENGTH];
        pbkdf2_hmac::<Sha256>(
            hardware_id.to_string().as_bytes(),
            SALT,
            PBKDF2_ITERATIONS,
            &mut key,
        );
        info!("Deriving encryption key took {:.2?}", start_time.elapsed());
        key
    }

    pub async fn load(&mut self) {
        if !self.path.exists() { return }

        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(err) => {
                error!("Failed to load server credentials from {:?}: {}", self.path, err);
                return;
            }
        };

        let decrypted = match self.decrypt(&bytes) {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Failed to decrypt credentials from {:?} - file may be corrupted or from different hardware: {}",
                    self.path, err
                );
                return;
            }
        };

        match bson::deserialize_from_slice::<StoredAuthTokens>(&decrypted) {
            Err(e) => error!("Failed to parse server credentials from {:?}: {}", self.path, e),
            Ok(stored_tokens) => {
                *self.profile.lock().await = stored_tokens.profile_uuid;
                self.update_tokens(AuthTokens {
                    access_token: stored_tokens.access_token,
                    refresh_token: stored_tokens.refresh_token,
                    expires_at: stored_tokens.expires_at
                }).await;
                info!("Loaded server credentials successfully");
            }
        }
    }

    pub async fn save(&self) -> Result<(), Box<dyn Error>> {
        let lock = self.tokens.lock().await;
        let Some(tokens) = &*lock else {
            return Err("No tokens available to save.".into())
        };

        let stored_tokens = StoredAuthTokens {
            access_token: tokens.refresh_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            expires_at: tokens.expires_at,
            profile_uuid: self.profile.lock().await.clone()
        };

        let plaintext = bson::serialize_to_vec(&stored_tokens)?;
        let encrypted = self.encrypt(&self.encryption_key, &plaintext)?;
        fs::write(&self.path, encrypted)?;

        info!("Saved server credentials successfully");
        Ok(())
    }

    fn encrypt(&self, key: &[u8; KEY_LENGTH], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = Aes256Gcm::new(key.into());
        let mut iv = [0u8; IV_LENGTH];

        rand::rng().fill_bytes(&mut iv);
        let nonce = aes_gcm::Nonce::try_from(iv).map_err(|e| e.to_string())?;
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| e.to_string())?;

        let mut result = Vec::with_capacity(IV_LENGTH + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if encrypted.len() < IV_LENGTH {
            return Err("Encrypted data too short".into());
        }

        let cipher = Aes256Gcm::new((&self.encryption_key).into());
        let (iv, ciphertext) = encrypted.split_at(IV_LENGTH);
        let nonce = aes_gcm::Nonce::try_from(iv).map_err(|e| e.to_string())?;

        cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| e.to_string().into())
    }
}