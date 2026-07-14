//! Session layer with shared defaults.

use tower_sessions::cookie::{Cookie, Key, SameSite};
use tower_sessions::{Expiry, SessionManagerLayer, SessionStore, service::SignedCookie};

/// Whether cookies should carry the `Secure` flag.
/// True in release builds, false in debug (allows local HTTP development).
pub const SECURE_COOKIES: bool = !cfg!(debug_assertions);

/// Build a session management layer with shared defaults:
///
/// - `SameSite::Lax`
/// - Signed cookies
/// - 7-day inactivity expiry
/// - Always save (even if unchanged)
///
/// `cookie_name` should be unique per service to allow simultaneous
/// sessions (e.g. `"myapp_sid"`, `"myadmin_sid"`).
pub fn build_session_layer<S: SessionStore>(
    store: S,
    signing_key: Key,
    cookie_name: &'static str,
    secure: bool,
) -> SessionManagerLayer<S, SignedCookie> {
    SessionManagerLayer::new(store)
        .with_name(cookie_name)
        .with_same_site(SameSite::Lax)
        .with_signed(signing_key)
        .with_secure(secure)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(7)))
        .with_always_save(true)
}

/// Format a `Set-Cookie` header value that removes a session cookie.
///
/// Mirrors the attributes set by [`build_session_layer`] (path `/`,
/// `SameSite::Lax`, `HttpOnly`) so the browser matches and deletes the right
/// cookie. Use it to drop a broken session immediately so the next request
/// doesn't loop on the same error.
pub fn clear_session_cookie_header(cookie_name: &str, secure: bool) -> String {
    let mut cookie = Cookie::build((cookie_name, ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .build();
    cookie.make_removal();
    cookie.to_string()
}
