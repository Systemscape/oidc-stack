#![deny(missing_docs)]
//! OIDC building blocks for Rust services.
//!
//! Two independent halves, selected by feature:
//! - **`validator`** (+ **`dropshot`**): local JWT validation against a
//!   cached, background-refreshed JWKS, for resource servers that accept
//!   bearer tokens. The `dropshot` feature adds a request extractor.
//! - **`bff`**: axum-oidc + tower-sessions SSO stack for web services that
//!   own the login flow: session cookie, CSRF protection, `/auth/*` routes.
//!
//! Extras: **`proxy`** (forward requests to a backend with the session's
//! bearer token), **`signed-request`** (HMAC-SHA256 inter-service requests).

pub mod discovery;

#[cfg(feature = "bff")]
pub mod bff;
#[cfg(feature = "dropshot")]
pub mod dropshot;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "signed-request")]
pub mod signed_request;
#[cfg(feature = "validator")]
pub mod validator;
