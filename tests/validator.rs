//! End-to-end validator tests against a mocked OIDC provider.
//!
//! wiremock serves the discovery document and a JWKS containing a symmetric
//! (`oct`) key; tokens are minted locally with the same secret, so the full
//! discovery -> JWKS fetch -> validation path runs without a real provider.
#![cfg(feature = "validator")]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use oidc_stack::validator::{Claims, TokenValidator, ValidatorConfig, ValidatorError};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KID: &str = "itest-key";
const SECRET: &[u8] = b"integration-test-secret";
const CLIENT_ID: &str = "itest-client";

/// Mock provider serving a discovery document and a single-key JWKS.
async fn mock_provider() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [{
                "kty": "oct",
                "kid": KID,
                "alg": "HS256",
                "k": URL_SAFE_NO_PAD.encode(SECRET),
            }]
        })))
        .mount(&server)
        .await;
    server
}

async fn connect(server: &MockServer) -> TokenValidator {
    TokenValidator::connect(ValidatorConfig {
        issuer: server.uri().parse().unwrap(),
        client_id: CLIENT_ID.into(),
        additional_audiences: vec![],
        // No background refresh task in tests.
        discovery_refresh_interval_seconds: 0,
    })
    .await
    .expect("connect against mock provider")
}

fn mint(server: &MockServer, kid: &str, aud: &str, expires_in_secs: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &json!({
            "sub": "user-1",
            "iss": server.uri(),
            "aud": aud,
            "exp": now + expires_in_secs,
            "groups": ["users"],
        }),
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

#[tokio::test]
async fn accepts_valid_token() {
    let server = mock_provider().await;
    let validator = connect(&server).await;
    let claims: Claims = validator
        .validate_token(&mint(&server, KID, CLIENT_ID, 3600))
        .expect("valid token accepted");
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.groups, vec!["users"]);
}

#[tokio::test]
async fn rejects_expired_token() {
    let server = mock_provider().await;
    let validator = connect(&server).await;
    // Well past jsonwebtoken's default 60s leeway.
    let result = validator.validate_token::<Claims>(&mint(&server, KID, CLIENT_ID, -3600));
    assert!(
        matches!(result, Err(ValidatorError::TokenExpired)),
        "{result:?}"
    );
}

#[tokio::test]
async fn rejects_wrong_audience() {
    let server = mock_provider().await;
    let validator = connect(&server).await;
    let result = validator.validate_token::<Claims>(&mint(&server, KID, "other-client", 3600));
    assert!(
        matches!(result, Err(ValidatorError::InvalidAudience)),
        "{result:?}"
    );
}

#[tokio::test]
async fn rejects_unknown_key_id() {
    let server = mock_provider().await;
    let validator = connect(&server).await;
    let result = validator.validate_token::<Claims>(&mint(&server, "unknown-kid", CLIENT_ID, 3600));
    assert!(
        matches!(result, Err(ValidatorError::KeyNotFound(_))),
        "{result:?}"
    );
}
