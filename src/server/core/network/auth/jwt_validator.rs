use subtle::ConstantTimeEq;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::crypto::verify;
use jsonwebtoken::errors::ErrorKind::MissingRequiredClaim;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use log::info;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OnceCell, Semaphore};
use uuid::Uuid;
use crate::server::core::network::auth::server_auth_manager::ServerAuthManager;
use crate::server::core::network::auth::services::session_service::{SessionService, SESSION_SERVICE_URL};

const JWK_CACHE_EXPIRY: Duration = Duration::from_secs(3600);
const ALGORITHM: Algorithm = Algorithm::EdDSA;
const LEEWAY_SECONDS: u64 = 300;

#[derive(Debug)]
pub struct JWTValidator {
    session_service: Arc<SessionService>,
    jwks: Mutex<Option<(JwkSet, Instant)>>,
    is_fetching: AtomicBool,
    fetch_done: Notify,
}

impl JWTValidator {
    pub async fn new(session_service: Arc<SessionService>) -> Self {
        Self {
            jwks: Mutex::new(None),
            session_service: session_service.clone(),
            is_fetching: AtomicBool::new(true),
            fetch_done: Notify::new(),
        }
    }

    pub async fn validate_token(&self, access_token: &str, client_cert: &Vec<CertificateDer<'_>>) -> Result<Claims, String> {
        validate_jwt_structure(access_token, "Identity Token")?;

        let claims = self.verify_signature::<Claims>(access_token).await?;
        validate_claims(&claims)?;
        validate_certificate_binding(&claims, client_cert)?;

        Ok(claims)
    }

    pub async fn validate_identity_token(&self, token: &str) -> Result<Claims, String> {
        validate_jwt_structure(token, "Identity Token")?;

        let claims = self.verify_signature::<Claims>(token).await?;
        validate_claims(&claims)?;

        Ok(claims)
    }

    async fn verify_signature<T: DeserializeOwned>(&self, token: &str) -> Result<T, String> {
        // Fetch JWKS
        let jwks = match self.get_jwks(false).await {
            None => self.get_jwks(true).await
                .ok_or_else(|| "Failed to fetch JWKS".to_string())?,
            Some(jwks) => jwks
        };

        // Decode header to get kid
        let header = decode_header(token)
            .map_err(|e| format!("Failed to decode JWT header: {}", e))?;

        // Find matching key from JWKS
        let jwk = find_key(&jwks, header.kid.as_deref())
            .ok_or_else(|| format!("No Ed25519 key found for kid={:?}", header.kid))?;

        // Create DecodingKey from JWK
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| format!("Failed to create decoding key: {}", e))?;

        // Decode and verify
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        let token_data = decode::<T>(token, &decoding_key, &validation)
            .map_err(|e| format!("JWT signature verification failed: {}", e))?;

        Ok(token_data.claims)
    }

    async fn get_jwks(&self, force: bool) -> Option<JwkSet> {
        if !force {
            // Check cached value
            if let Some((jwks_data, expiry)) = self.jwks.lock().unwrap().as_ref() {
                if expiry.elapsed() < JWK_CACHE_EXPIRY {
                    return Some(jwks_data.clone());
                }
            }
        }

        // Start fetch if not already fetching
        if !self.is_fetching.swap(true, Ordering::Relaxed) {
            self.fetch_jwks();
        }

        // Wait for fetch to complete
        self.fetch_done.notified().await;
        self.jwks.lock().unwrap().as_ref().map(|(jwks, _)| jwks.clone())
    }

    pub fn fetch_jwks(&self) {
        tokio::spawn(async move {
            let validator = ServerAuthManager::get().jwt_validator.clone();
            if let Some(jwks) = validator.session_service.fetch_jwks().await {
                *validator.jwks.lock().unwrap() = Some((jwks, Instant::now()));
            }
            validator.is_fetching.store(false, Ordering::Relaxed);
            validator.fetch_done.notify_waiters();
        });
    }
}

fn validate_jwt_structure(token: &str, token_type: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err(format!("{} is empty.", token_type))
    }

    let parts: Vec<&str> = token.split(".").collect();
    if parts.len() != 3 {
        return Err(format!("{} has invalid format.", token_type))
    }

    let sig_len = parts[2].len();
    match sig_len {
        0 => Err(format!("{} has empty signature.", token_type)),
        1..80 | 91.. => Err(format!("{} has invalid signature length {}.", token_type, sig_len)),
        _ => Ok(())
    }
}

fn validate_claims(claims: &Claims) -> Result<(), String> {
    // Verify issuer
    if SESSION_SERVICE_URL != claims.iss {
        return Err(format!(
            "Invalid issuer: expected {}, got {}",
            SESSION_SERVICE_URL, claims.iss
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check expiration
    if let Some(exp) = claims.exp {
        if now >= exp + LEEWAY_SECONDS {
            return Err(format!(
                "Token expired (exp: {}, now: {})",
                exp, now
            ));
        }
    } else {
        return Err("Token missing expiration claim".into());
    }

    // Check not before
    if let Some(nbf) = claims.nbf {
        if now < nbf.saturating_sub(LEEWAY_SECONDS) {
            return Err(format!(
                "Token not yet valid (nbf: {}, now: {})",
                nbf, now
            ));
        }
    }

    // Check issued at
    if let Some(iat) = claims.iat {
        if iat > now + LEEWAY_SECONDS {
            return Err(format!(
                "Token issued in the future (iat: {}, now: {})",
                iat, now
            ));
        }
    }

    // Check UUID
    if Uuid::parse_str(&claims.sub).is_err() {
        return Err("Token has invalid or missing subject UUID".into());
    }

    Ok(())
}

fn find_key<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    for jwk in &jwks.keys {
        // Check if this is an Ed25519 key (OctetKeyPair)
        if !matches!(
                &jwk.algorithm,
                jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(_)
            ) {
            continue;
        }

        // Check if kid matches (if provided)
        if let Some(requested_kid) = kid {
            if let Some(key_id) = &jwk.common.key_id {
                if requested_kid != key_id {
                    continue;
                }
            }
        }

        return Some(jwk);
    }

    None
}

fn validate_certificate_binding(claims: &Claims, client_cert: &Vec<CertificateDer<'_>>) -> Result<(), String> {
    // The JWT must contain the fingerprint (cnf.x5t#S256)
    let Some(jwt_fp) = claims.cnf.as_ref().map(|c| c.certificate_fingerprint.as_str()) else {
        return Err("Missing certificate fingerprint".into())
    };

    if jwt_fp.is_empty() {
        return Err("Empty certificate fingerprint".into());
    }

    // The mTLS connection must have presented a certificate
    let Some(client_cert) = client_cert.first() else {
        return Err("Missing client certificate".into())
    };

    // Compute the fingerprint of the presented certificate
    let actual_fp = compute_certificate_fingerprint(client_cert).ok_or_else(|| {
        "Failed to compute client certificate fingerprint".to_string()
    })?;

    // Compare in constant time
    if jwt_fp.as_bytes().ct_eq(actual_fp.as_bytes()).unwrap_u8() != 1 {
        return Err("Certificate fingerprint mismatch".into());
    }

    info!("Certificate validated successfully");
    Ok(())
}

/// Compute the SHA‑256 fingerprint of a DER‑encoded certificate and return a
/// URL‑safe base64 string without padding.
pub fn compute_certificate_fingerprint(cert: &CertificateDer<'_>) -> Option<String> {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let hash = hasher.finalize();
    Some(URL_SAFE_NO_PAD.encode(hash))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: Option<u64>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,

    pub aud: Option<String>,
    pub username: Option<String>,
    pub ip: Option<String>,
    pub cnf: Option<CNF>,

    pub scope: Option<String>,
    pub profile: Option<ProfileData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CNF {
    #[serde(rename = "x5t#S256")]
    pub certificate_fingerprint: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    pub username: Option<String>,
    pub skin: Option<String>,
    pub entitlements: Option<Vec<String>>,
}