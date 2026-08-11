//! axum-oidc + tower-sessions SSO stack for BFF-style web services.
//!
//! [`BffAuth::connect`] builds the OIDC client (with discovery preflight and
//! background rediscovery), the signed-session layer, and the CSRF layer;
//! [`BffAuth::attach`] wires them plus the `/auth/*` routes around your
//! application router in the correct order.

mod csrf;
mod session;
mod stack;

pub use csrf::build_csrf_layer;
pub use session::{SECURE_COOKIES, build_session_layer, clear_session_cookie_header};
pub use stack::{AuthMeResponse, BffAuth, BffError, BffOptions};

// Re-export the types consumers need to build a [`BffConfig`] and read the
// session's claims/token in handlers, so they don't have to depend on
// axum-oidc directly.
pub use axum_oidc::openidconnect::{ClientId, ClientSecret, IssuerUrl};
pub use axum_oidc::{OidcAccessToken, OidcClaims};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_oidc::openidconnect::core::CoreGenderClaim;
use axum_oidc::{AdditionalClaims, OidcClient, OidcSession, Session};
use serde::{Deserialize, Serialize};
use tower_sessions::Session as TowerSession;

use crate::discovery::default_refresh_interval_seconds;

/// Additional OIDC claims carrying the provider's group memberships.
///
/// Requires requesting a scope that yields a `groups` claim (see
/// [`BffOptions::scopes`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GroupsClaims {
    /// Group memberships from the provider.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl GroupsClaims {
    /// Whether `group` is among the user's groups.
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }
}

impl AdditionalClaims for GroupsClaims {}
impl axum_oidc::openidconnect::AdditionalClaims for GroupsClaims {}

/// Configuration for an OIDC login client (confidential client, code flow).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BffConfig {
    /// Issuer URL, e.g. `https://auth.example.com/auth/v1`.
    pub issuer: IssuerUrl,
    /// OIDC client id.
    pub client_id: ClientId,
    /// OIDC client secret.
    pub client_secret: ClientSecret,
    /// How often (seconds) to re-run OIDC discovery in the background so the
    /// cached JWKS picks up provider key rotation without a restart. 0
    /// disables.
    #[serde(default = "default_refresh_interval_seconds")]
    pub discovery_refresh_interval_seconds: u64,
}

/// Session key under which the opaque axum-oidc session blob is stored
/// inside the tower-sessions session.
const OIDC_SESSION_KEY: &str = "axum-oidc";

/// Adapter implementing axum-oidc's [`Session`] trait over tower-sessions.
///
/// axum-oidc is session-store agnostic: the integrator supplies the storage.
/// This persists the opaque `OidcSession` blob in the tower-sessions session
/// under a fixed key, so the OIDC flow shares the same signed session cookie
/// as the rest of the app.
pub struct OidcSessionStore {
    /// The underlying tower-sessions session, extracted per request.
    session: TowerSession,
}

impl<S: Send + Sync> FromRequestParts<S> for OidcSessionStore {
    type Rejection = <TowerSession as FromRequestParts<S>>::Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            session: TowerSession::from_request_parts(parts, state).await?,
        })
    }
}

impl<AC: AdditionalClaims> Session<AC> for OidcSessionStore {
    type Error = tower_sessions::session::Error;

    async fn get(&self) -> Result<OidcSession<AC, CoreGenderClaim>, Self::Error> {
        Ok(self
            .session
            .get(OIDC_SESSION_KEY)
            .await?
            .unwrap_or_default())
    }

    async fn set(&mut self, value: OidcSession<AC, CoreGenderClaim>) -> Result<(), Self::Error> {
        // Serialize up front (`insert` does this anyway) so the stored shape
        // can be checked for a missing refresh token before it is written.
        let value = serde_json::to_value(value)?;
        if authenticated_without_refresh_token(&value) {
            tracing::warn!(
                "OIDC provider issued no refresh token. This session will start \
                 returning 401s as soon as its access token expires, and cannot \
                 recover: the auth middleware only refreshes when it has a \
                 refresh token, so requests silently arrive without an access \
                 token. Enable the refresh_token grant for this client (Rauthy: \
                 client -> Allowed Flows -> refresh_token), or request the \
                 `offline_access` scope if your provider requires it."
            );
        }
        self.session
            .insert_value(OIDC_SESSION_KEY, value)
            .await
            .map(|_| ())
    }
}

/// Return whether a stored session is authenticated but carries no refresh token.
/// This indicates a provider misconfiguration that strands the session at token expiry.
///
/// axum-oidc keeps `OidcSession`'s variants and fields private, so its derived
/// `Serialize` is the only way to see inside: a transparent newtype over an
/// externally tagged enum, making an authenticated session
/// `{"Authenticated": {"authenticated": {…}, "refresh_token": <str>|null}}`.
/// Anything else (`"Unauthenticated"`, `{"Pending": …}`, an unrecognised
/// shape) is not a misconfiguration and must stay quiet.
fn authenticated_without_refresh_token(value: &serde_json::Value) -> bool {
    let Some(session) = value.get("Authenticated") else {
        return false;
    };
    session
        .get("refresh_token")
        .is_none_or(serde_json::Value::is_null)
}

/// Spawn a background task that periodically re-runs OIDC discovery so the
/// cached JWKS refreshes when the provider rotates signing keys, without a
/// process restart.
///
/// [`OidcClient`] holds its metadata behind an `ArcSwap`, so each successful
/// rediscover propagates atomically to every middleware clone. Pass the
/// *advertised* issuer (the one returned by
/// [`crate::discovery::discovered_issuer`] and fed into `.discover()`);
/// `rediscover` re-checks it byte-for-byte against the discovery document.
/// An interval of 0 disables the task.
pub fn spawn_rediscover_task<AC>(client: OidcClient<AC>, issuer: IssuerUrl, interval_seconds: u64)
where
    AC: AdditionalClaims + 'static,
{
    if interval_seconds == 0 {
        tracing::info!("OIDC discovery refresh disabled (interval = 0)");
        return;
    }

    let period = std::time::Duration::from_secs(interval_seconds);
    tracing::info!("Spawning OIDC discovery refresh task (interval = {period:?})");

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        // If a tick is missed, resume from when the rediscover finished
        // rather than bursting to catch up.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // The first tick fires immediately; startup discovery already ran.
        tick.tick().await;
        loop {
            tick.tick().await;
            match client.rediscover(issuer.clone()).await {
                Ok(()) => tracing::debug!("OIDC discovery refreshed"),
                Err(e) => tracing::warn!("OIDC discovery refresh failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Canary: `authenticated_without_refresh_token` reads a JSON shape
    /// axum-oidc never promised. `Default` is the only `OidcSession` an
    /// outsider can construct, but it still pins the two assumptions that
    /// would break silently on an upgrade: the newtype is transparent, and the
    /// inner enum is externally tagged.
    #[test]
    fn oidc_session_serializes_as_externally_tagged_enum() {
        let value = serde_json::to_value(OidcSession::<GroupsClaims, CoreGenderClaim>::default())
            .expect("serializes");
        assert_eq!(value, json!("Unauthenticated"));
    }

    #[test]
    fn warns_only_for_an_authenticated_session_without_a_refresh_token() {
        let authenticated = |refresh_token| {
            json!({ "Authenticated": {
                "authenticated": { "id_token": "j.w.t", "access_token": "at", "user_info": {} },
                "refresh_token": refresh_token,
            }})
        };

        // The bug this exists to announce.
        assert!(authenticated_without_refresh_token(&authenticated(json!(
            null
        ))));
        // A healthy session must stay quiet.
        assert!(!authenticated_without_refresh_token(&authenticated(json!(
            "rt"
        ))));
        // Neither is a misconfiguration: no session, or a login in flight.
        assert!(!authenticated_without_refresh_token(&json!(
            "Unauthenticated"
        )));
        assert!(!authenticated_without_refresh_token(
            &json!({ "Pending": { "nonce": "n" } })
        ));
        // An unrecognised shape is not evidence of a missing refresh token.
        assert!(!authenticated_without_refresh_token(&json!({})));
        // An authenticated session missing the field entirely still has none.
        assert!(authenticated_without_refresh_token(
            &json!({ "Authenticated": { "authenticated": {} } })
        ));
    }
}
