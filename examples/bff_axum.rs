//! Minimal axum BFF with the full login stack.
//!
//! Run against a real provider (which must have
//! `http://127.0.0.1:8080/auth/callback` registered as a redirect URL):
//!
//! ```sh
//! OIDC_ISSUER=https://auth.example.com/auth/v1 OIDC_CLIENT_ID=my-app \
//!     OIDC_CLIENT_SECRET=... cargo run --example bff_axum --features bff
//! ```
//!
//! Then open <http://127.0.0.1:8080/auth/login>; after signing in, try
//! `/auth/me` and `/api/hello`.

use axum::{Router, routing::get};
use oidc_stack::bff::{
    BffAuth, BffConfig, BffOptions, ClientId, ClientSecret, GroupsClaims, IssuerUrl, OidcClaims,
};
use tower_sessions::MemoryStore;
use tower_sessions::cookie::Key;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

#[tokio::main]
async fn main() {
    let config = BffConfig {
        issuer: IssuerUrl::new(env("OIDC_ISSUER")).expect("issuer URL"),
        client_id: ClientId::new(env("OIDC_CLIENT_ID")),
        client_secret: ClientSecret::new(env("OIDC_CLIENT_SECRET")),
        discovery_refresh_interval_seconds: 60,
    };
    let public_url = "http://127.0.0.1:8080";

    let bff = BffAuth::connect(
        &config,
        public_url,
        MemoryStore::default(),
        Key::generate(),
        BffOptions {
            cookie_name: "example_sid",
            ..Default::default()
        },
    )
    .await
    .expect("connect to OIDC provider");

    // Attached routes see the session's claims; requiring `OidcClaims`
    // rejects requests without a login (401), it does not redirect.
    let protected = Router::new().route(
        "/api/hello",
        get(|claims: OidcClaims<GroupsClaims>| async move {
            format!("hello {}", claims.subject().as_str())
        }),
    );

    let app = bff.attach(protected);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind");
    println!("open http://127.0.0.1:8080/auth/login");
    axum::serve(listener, app).await.expect("serve");
}
