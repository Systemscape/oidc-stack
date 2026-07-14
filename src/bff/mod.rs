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
        self.session.insert(OIDC_SESSION_KEY, value).await
    }
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
