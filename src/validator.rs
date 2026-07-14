//! Local JWT validation for OIDC resource servers.
//!
//! Validates bearer tokens against the provider's JWKS, cached in memory and
//! refreshed in the background, so no per-request call to the provider is
//! needed.

use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use jwks::Jwks;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::discovery::{
    DiscoveryError, default_refresh_interval_seconds, discovered_issuer, discovery_url,
};

/// Configuration for [`TokenValidator`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Issuer URL, e.g. `https://auth.example.com/auth/v1`.
    pub issuer: Url,
    /// OAuth client id, accepted as token audience.
    pub client_id: String,
    /// Extra accepted audiences besides `client_id`.
    #[serde(default)]
    pub additional_audiences: Vec<String>,
    /// How often (seconds) to re-fetch the JWKS in the background so provider
    /// key rotation is picked up without a restart. 0 disables.
    #[serde(default = "default_refresh_interval_seconds")]
    pub discovery_refresh_interval_seconds: u64,
}

/// Errors from [`TokenValidator`].
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum ValidatorError {
    #[error("OIDC discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("Failed to decode JWT header: {0}")]
    HeaderDecode(String),
    #[error("JWT header missing Key ID (kid)")]
    MissingKeyId,
    #[error("Failed to fetch JWKS: {0}")]
    JwksFetch(String),
    #[error("No matching key found for Key ID: {0}")]
    KeyNotFound(String),
    #[error("JWT validation failed: {0}")]
    ValidationFailed(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid audience")]
    InvalidAudience,
}

/// Standard OIDC claims extracted from a validated access token.
///
/// [`TokenValidator::validate_token`] is generic; use this type unless you
/// need provider-specific claims.
#[derive(Debug, Deserialize)]
pub struct Claims {
    /// Subject identifier (unique user id from the OIDC provider).
    pub sub: String,
    /// Issuer.
    pub iss: Option<String>,
    /// Audience.
    #[serde(default)]
    pub aud: Audience,
    /// Expiration time (validated by jsonwebtoken).
    pub exp: Option<u64>,
    /// Groups the user belongs to (commonly used for authorization).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Given name.
    #[serde(default)]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(default)]
    pub family_name: Option<String>,
}

/// Audience claim: a single string or an array of strings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience string.
    Single(String),
    /// Multiple audiences.
    Multiple(Vec<String>),
    /// No audience specified.
    #[default]
    None,
}

impl Audience {
    /// Whether the audience contains `expected`.
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(aud) => aud == expected,
            Audience::Multiple(auds) => auds.iter().any(|a| a == expected),
            Audience::None => false,
        }
    }
}

/// Validates JWT access tokens against the provider's JWKS.
///
/// Cloning is cheap: every clone shares the same `ArcSwap<Jwks>`, so the
/// background refresh spawned by [`TokenValidator::connect`] propagates to
/// all of them.
#[derive(Clone)]
pub struct TokenValidator {
    /// JWKS public keys, held behind an `ArcSwap` so the background refresh
    /// can replace them lock-free when the provider rotates signing keys.
    jwks: Arc<ArcSwap<Jwks>>,
    /// Discovery URL used to (re-)fetch the JWKS.
    jwks_url: String,
    /// All accepted audience values (client_id + additional audiences).
    audiences: Vec<String>,
    /// The expected issuer URL for validation (as advertised by discovery).
    issuer: String,
}

impl std::fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenValidator")
            .field("audiences", &self.audiences)
            .field("issuer", &self.issuer)
            .field("jwks", &format!("<{} keys>", self.jwks.load().keys.len()))
            .finish()
    }
}

impl TokenValidator {
    /// Run OIDC discovery, fetch the JWKS, and spawn the background refresh
    /// task (interval from
    /// [`discovery_refresh_interval_seconds`](ValidatorConfig::discovery_refresh_interval_seconds),
    /// 0 disables).
    ///
    /// Tokens are validated against the *advertised* issuer; the configured
    /// `issuer` only locates the discovery endpoint (see
    /// [`discovered_issuer`]).
    pub async fn connect(config: ValidatorConfig) -> Result<Self, ValidatorError> {
        let issuer = discovered_issuer(config.issuer.as_str()).await?;
        debug!("Discovered issuer: {issuer}");

        let jwks_url = discovery_url(config.issuer.as_str());
        let jwks = Jwks::from_oidc_url(jwks_url.as_str())
            .await
            .map_err(|e| ValidatorError::JwksFetch(e.to_string()))?;
        debug!("Fetched {} keys from JWKS endpoint", jwks.keys.len());

        let mut audiences = vec![config.client_id];
        audiences.extend(config.additional_audiences);
        debug!("Accepted audiences: {audiences:?}");

        let validator = Self {
            jwks: Arc::new(ArcSwap::from_pointee(jwks)),
            jwks_url,
            audiences,
            issuer,
        };
        validator.spawn_refresh_task(config.discovery_refresh_interval_seconds);
        Ok(validator)
    }

    /// Re-fetch the JWKS from the provider and atomically swap it in.
    pub async fn refresh_jwks(&self) -> Result<(), ValidatorError> {
        let jwks = Jwks::from_oidc_url(self.jwks_url.as_str())
            .await
            .map_err(|e| ValidatorError::JwksFetch(e.to_string()))?;
        debug!("Refreshed {} keys from JWKS endpoint", jwks.keys.len());
        self.jwks.store(Arc::new(jwks));
        Ok(())
    }

    /// Spawn a background task that re-fetches the JWKS on a timer.
    fn spawn_refresh_task(&self, interval_seconds: u64) {
        if interval_seconds == 0 {
            info!("JWKS refresh disabled (interval = 0)");
            return;
        }

        let validator = self.clone();
        let period = std::time::Duration::from_secs(interval_seconds);
        info!("Spawning JWKS refresh task (interval = {period:?})");

        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            // If a tick is missed, resume from when the refresh finished
            // rather than bursting to catch up.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick fires immediately; startup already fetched.
            tick.tick().await;
            loop {
                tick.tick().await;
                match validator.refresh_jwks().await {
                    Ok(()) => debug!("JWKS refreshed"),
                    Err(e) => warn!("JWKS refresh failed: {e}"),
                }
            }
        });
    }

    /// Validate a JWT access token (signature, exp/nbf, issuer, audience)
    /// and deserialize its claims.
    pub fn validate_token<C: DeserializeOwned>(&self, token: &str) -> Result<C, ValidatorError> {
        let header = decode_header(token).map_err(|e| {
            error!("Failed to decode JWT header: {e}");
            ValidatorError::HeaderDecode(e.to_string())
        })?;

        let kid = header.kid.as_ref().ok_or_else(|| {
            error!("JWT header missing Key ID (kid)");
            ValidatorError::MissingKeyId
        })?;

        // Snapshot the current JWKS; a background refresh may swap in new
        // keys at any time, so hold the guard for the rest of this call.
        let jwks = self.jwks.load();

        let jwk = jwks.keys.get(kid).ok_or_else(|| {
            debug!(
                "No matching key found for Key ID: {kid}. Available keys: {:?}",
                jwks.keys.keys().collect::<Vec<_>>()
            );
            ValidatorError::KeyNotFound(kid.clone())
        })?;

        // Defense in depth: jsonwebtoken binds each DecodingKey to an
        // AlgorithmFamily and rejects family mismatches, but don't rely
        // solely on a dependency internal. When the JWKS entry declares an
        // `alg` (RFC 7517 makes it optional), require the token header to
        // match it so a forged `alg` cannot select a different primitive.
        if let Some(key_alg) = &jwk.alg {
            let expected = Algorithm::from_str(&key_alg.to_string()).map_err(|_| {
                ValidatorError::ValidationFailed(format!(
                    "JWKS key declares unsupported alg {key_alg}"
                ))
            })?;
            if header.alg != expected {
                error!(
                    "Token alg {:?} does not match JWKS key alg {key_alg}",
                    header.alg
                );
                return Err(ValidatorError::ValidationFailed(format!(
                    "token algorithm {:?} does not match key algorithm {key_alg}",
                    header.alg
                )));
            }
        }

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(
            &self
                .audiences
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );

        let token_data = decode::<C>(token, &jwk.decoding_key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => {
                    error!("Token has expired");
                    ValidatorError::TokenExpired
                }
                ErrorKind::InvalidAudience => {
                    error!("Invalid audience. Expected one of: {:?}", self.audiences);
                    ValidatorError::InvalidAudience
                }
                _ => {
                    error!("JWT validation failed: {e}");
                    ValidatorError::ValidationFailed(e.to_string())
                }
            }
        })?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::KeyAlgorithm;
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
    use jwks::{Jwk, Jwks};
    use std::collections::HashMap;

    #[derive(serde::Serialize)]
    struct DummyClaims {
        sub: &'static str,
    }

    /// A token whose header `alg` disagrees with the algorithm the JWKS
    /// key declares must be rejected by the alg pin, before any signature
    /// check (classic algorithm-confusion hardening).
    #[test]
    fn rejects_token_alg_not_matching_jwk_alg() {
        let kid = "test-kid";
        let mut keys = HashMap::new();
        keys.insert(
            kid.to_string(),
            Jwk {
                alg: Some(KeyAlgorithm::EdDSA),
                decoding_key: DecodingKey::from_secret(b"unused-on-this-path"),
            },
        );
        let validator = TokenValidator {
            jwks: Arc::new(ArcSwap::from_pointee(Jwks { keys })),
            jwks_url: "https://issuer.example/.well-known/openid-configuration".to_string(),
            audiences: vec!["aud".to_string()],
            issuer: "https://issuer.example".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        let token = encode(
            &header,
            &DummyClaims { sub: "attacker" },
            &EncodingKey::from_secret(b"forged"),
        )
        .expect("token encodes");

        match validator.validate_token::<Claims>(&token) {
            Err(ValidatorError::ValidationFailed(msg)) => assert!(
                msg.contains("does not match key algorithm"),
                "expected alg-pin rejection, got: {msg}"
            ),
            other => panic!("expected ValidationFailed from alg pin, got {other:?}"),
        }
    }
}
