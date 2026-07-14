# oidc-stack

OIDC building blocks for Rust services. Two independent halves, selected by
feature; everything is off by default.

| Feature | Contents |
|---|---|
| `validator` | Local JWT validation against a cached, background-refreshed JWKS (resource servers). Framework-free. |
| `dropshot` | `Authed<C>` extractor on top of `validator` for dropshot servers. |
| `bff` | axum-oidc + tower-sessions SSO stack: login flow, signed session cookie, CSRF layer, `/auth/*` routes. |
| `proxy` | Forward requests to a backend API with the session's bearer token (implies `bff`). |
| `signed-request` | HMAC-SHA256 `{timestamp}.{body}` signing/verification for inter-service calls. |

## Resource server (dropshot)

```rust
let validator = TokenValidator::connect(config.oidc).await?; // discovery + JWKS + refresh task

impl OidcAuth for AppContext {
    type Identity = User;
    fn validator(&self) -> &TokenValidator { &self.validator }
    async fn resolve(&self, claims: Claims, _token: &str) -> Result<User, HttpError> {
        // policy hook: group checks, user lookup/provisioning
        self.lookup_user(&claims.sub).await
    }
}

#[endpoint { method = GET, path = "/me" }]
async fn me(rqctx: RequestContext<AppContext>, auth: Authed<AppContext>) -> ... {
    let user = auth.0;
}
```

## Web service with login flow (axum)

```rust
let bff = BffAuth::connect(
    &config.oidc,
    &config.app.url,
    session_store, // any tower-sessions store; run migrations first
    signing_key,
    BffOptions {
        cookie_name: "myapp_sid",
        require_group: Some("myapp-admins".into()),
        ..Default::default()
    },
)
.await?;

let app = bff
    .attach(protected_routes) // mounts /auth/{login,logout,callback,clear,me}
    .layer(TraceLayer::new_for_http())
    .fallback_service(static_files);
```

CSRF is origin-based (`Sec-Fetch-Site` / `Origin`, tower-http `CsrfLayer`):
mutating cross-origin requests get 403, the frontend sends no token.

## Testing

`cargo test --all-features` runs the unit tests plus `tests/validator.rs`,
which exercises discovery, JWKS fetch, and token validation end-to-end
against a wiremock provider (no network, no real IdP).

The examples compile-test the public API (`cargo check --examples
--all-features`) and run against a real provider for manual testing:

```sh
OIDC_ISSUER=... OIDC_CLIENT_ID=... cargo run --example dropshot_api --features dropshot
OIDC_ISSUER=... OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... cargo run --example bff_axum --features bff
```

## Version pins

`axum-oidc` is pre-release (`1.0.0-dev-2`); its types appear in the `bff`
public API, so consumers must track the same pin. Token validation uses
`jsonwebtoken` 10 + `jwks` 0.5 (aws-lc-rs backend).

## License

MIT
