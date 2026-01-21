use std::sync::LazyLock;
use std::time::Instant;
use serde::{Deserialize, Serialize};

// pub static SERVER_AUTH_MANAGER: LazyLock<ServerAuthManager> = LazyLock::new(ServerAuthManager::new);
// 
// pub struct ServerAuthManager {
//     auth_mode: _,
//     token_expiry: _,
//     game_session: _,
//     credential_store: _,
//     available_profiles: _,
//     pending_profiles: _,
//     pending_auth_mode: _,
//     server_certificate: _,
//     server_session_id: _,
// 
//     oauth_client: _,
//     session_service_client: _,
//     profile_service_client: _,
// }
// 
// impl ServerAuthManager {
//     fn new() -> Self {
//         todo!()
//     }
// }
// 
// pub struct OAuthTokens {
//     access_token: Option<String>,
//     refresh_token: Option<String>,
//     access_token_expiry: Option<Instant>
// }



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
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}
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