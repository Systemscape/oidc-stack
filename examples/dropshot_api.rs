//! Minimal dropshot resource server protected by `Authed`.
//!
//! Run against a real provider:
//!
//! ```sh
//! OIDC_ISSUER=https://auth.example.com/auth/v1 OIDC_CLIENT_ID=my-api \
//!     cargo run --example dropshot_api --features dropshot
//! curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/whoami
//! ```

use dropshot::{
    ApiDescription, ConfigDropshot, ConfigLogging, ConfigLoggingLevel, HttpError, HttpResponseOk,
    RequestContext, ServerBuilder, endpoint,
};
use oidc_stack::dropshot::{Authed, OidcAuth};
use oidc_stack::validator::{Claims, TokenValidator, ValidatorConfig};

struct AppContext {
    validator: TokenValidator,
}

impl OidcAuth for AppContext {
    type Identity = String;

    fn validator(&self) -> &TokenValidator {
        &self.validator
    }

    async fn resolve(&self, claims: Claims, _access_token: &str) -> Result<String, HttpError> {
        // Policy hook: check groups, look up or provision the user, etc.
        Ok(claims.sub)
    }
}

#[endpoint { method = GET, path = "/whoami" }]
async fn whoami(
    _rqctx: RequestContext<AppContext>,
    auth: Authed<AppContext>,
) -> Result<HttpResponseOk<String>, HttpError> {
    Ok(HttpResponseOk(auth.0))
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

#[tokio::main]
async fn main() {
    let config = ValidatorConfig {
        issuer: env("OIDC_ISSUER").parse().expect("issuer URL"),
        client_id: env("OIDC_CLIENT_ID"),
        additional_audiences: vec![],
        discovery_refresh_interval_seconds: 60,
    };
    let validator = TokenValidator::connect(config)
        .await
        .expect("OIDC discovery");

    let mut api = ApiDescription::new();
    api.register(whoami).expect("register endpoint");

    let logger = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Info,
    }
    .to_logger("dropshot_api")
    .expect("logger");

    println!("listening on http://127.0.0.1:8081 (GET /whoami)");
    ServerBuilder::new(api, AppContext { validator }, logger)
        .config(ConfigDropshot {
            bind_address: "127.0.0.1:8081".parse().unwrap(),
            ..Default::default()
        })
        .start()
        .expect("start server")
        .await
        .expect("server runs");
}
