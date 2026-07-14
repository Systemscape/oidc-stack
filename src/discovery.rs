//! OIDC discovery preflight helpers.

use serde::Deserialize;

/// Default background discovery/JWKS refresh interval (seconds).
pub fn default_refresh_interval_seconds() -> u64 {
    60
}

/// Errors from [`discovered_issuer`].
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The discovery endpoint could not be reached or returned a non-2xx.
    #[error("failed to fetch OIDC discovery: {0}")]
    Fetch(#[from] reqwest::Error),
    /// The `issuer` value in the discovery document is not a valid URL.
    #[error("invalid issuer in discovery document: {0}")]
    InvalidIssuer(#[from] url::ParseError),
}

/// Well-known discovery document URL for `issuer`.
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Fetch the provider's discovery document and return the *advertised*
/// issuer rather than the configured one.
///
/// OIDC libraries commonly enforce byte-for-byte equality between the
/// expected issuer and the discovery document's `issuer` claim, so a
/// provider that starts advertising e.g. a trailing slash breaks any config
/// that lacks it. Preflighting discovery and validating tokens (or running
/// `.discover()`) against the advertised issuer makes such provider changes
/// a no-op.
///
/// The returned string is the document's `issuer` value verbatim: it is
/// checked to parse as a URL but not re-serialized, to preserve equality.
pub async fn discovered_issuer(configured_issuer: &str) -> Result<String, DiscoveryError> {
    #[derive(Deserialize)]
    struct Discovery {
        issuer: String,
    }

    let discovery: Discovery = reqwest::get(discovery_url(configured_issuer))
        .await?
        .error_for_status()?
        .json()
        .await?;
    url::Url::parse(&discovery.issuer)?;
    Ok(discovery.issuer)
}
