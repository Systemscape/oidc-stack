//! CSRF protection.
//!
//! Wraps tower-http's [`CsrfLayer`], which enforces the cross-origin check
//! from the Go 1.25 scheme: mutating requests (POST/PUT/DELETE/PATCH) are
//! rejected with 403 unless `Sec-Fetch-Site` reports same-origin/none, or the
//! request's `Origin` matches the service. No per-request token state, so
//! the frontend needs no CSRF header.

use tower_http::csrf::CsrfLayer;
use tracing::warn;
use url::Url;

/// Build the shared CSRF protection layer.
///
/// `public_url` is the service's own public URL. Its origin
/// (`scheme://host[:port]`) is registered as a trusted origin so same-origin
/// mutating requests still pass when a reverse proxy rewrites `Host`. Modern
/// browsers are covered by `Sec-Fetch-Site` regardless; a URL that cannot be
/// reduced to a usable origin is logged and skipped, not treated as fatal.
pub fn build_csrf_layer(public_url: &str) -> CsrfLayer {
    let origin = match Url::parse(public_url) {
        Ok(url) => url.origin().ascii_serialization(),
        Err(e) => {
            warn!(
                "CSRF: cannot parse public URL {public_url:?} ({e}); relying on Sec-Fetch-Site only"
            );
            return CsrfLayer::new();
        }
    };

    match CsrfLayer::new().add_trusted_origin(&origin) {
        Ok(layer) => layer,
        Err(e) => {
            warn!(
                "CSRF: ignoring invalid trusted origin {origin:?} ({e}); relying on Sec-Fetch-Site only"
            );
            CsrfLayer::new()
        }
    }
}
