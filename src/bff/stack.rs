//! Turn-key assembly of the BFF auth stack.

use axum::{
    Json, Router,
    error_handling::HandleErrorLayer,
    extract::Request,
    http::{StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{any, get},
};
use axum_oidc::openidconnect::{IssuerUrl, Scope};
use axum_oidc::{
    OidcAuthLayer, OidcClaims, OidcClient, OidcLoginLayer, OidcRpInitiatedLogout,
    error::MiddlewareError, handle_oidc_redirect,
};
use serde::Serialize;
use tower::ServiceBuilder;
use tower_http::csrf::CsrfLayer;
use tower_sessions::{
    Session, SessionManagerLayer, SessionStore, cookie::Key, service::SignedCookie,
};

use super::{
    BffConfig, GroupsClaims, OidcSessionStore, SECURE_COOKIES, build_csrf_layer,
    build_session_layer, spawn_rediscover_task,
};
use crate::discovery::{DiscoveryError, discovered_issuer};

/// Errors from [`BffAuth::connect`].
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum BffError {
    #[error("OIDC discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("advertised issuer is not a valid issuer URL: {0}")]
    InvalidIssuer(#[from] url::ParseError),
    #[error("public URL is not a valid URI: {0}")]
    PublicUrl(#[from] axum::http::uri::InvalidUri),
    #[error("OIDC client setup failed: {0}")]
    Oidc(#[from] axum_oidc::error::Error),
}

/// Options for [`BffAuth::connect`]. Start from `Default` and override:
///
/// ```ignore
/// BffOptions {
///     cookie_name: "myapp_sid",
///     require_group: Some("myapp-admins".into()),
///     ..Default::default()
/// }
/// ```
pub struct BffOptions {
    /// Session cookie name; unique per service so simultaneous sessions work.
    pub cookie_name: &'static str,
    /// Where `/auth/login` redirects after a completed login.
    pub post_login_redirect: String,
    /// Where a failed `/auth/callback` redirects after flushing the session.
    pub callback_error_redirect: String,
    /// When set, every attached route and `/auth/me` require membership in
    /// this group: 401 without a session, 403 without the group.
    pub require_group: Option<String>,
    /// OIDC scopes to request. The `groups` claim usually needs a scope of
    /// its own.
    pub scopes: Vec<String>,
    /// `Secure` flag on the session cookie. Defaults to [`SECURE_COOKIES`]
    /// (true in release builds).
    pub secure_cookies: bool,
}

impl Default for BffOptions {
    fn default() -> Self {
        Self {
            cookie_name: "sid",
            post_login_redirect: "/".into(),
            callback_error_redirect: "/auth/clear".into(),
            require_group: None,
            scopes: ["profile", "email", "groups"].map(String::from).to_vec(),
            secure_cookies: SECURE_COOKIES,
        }
    }
}

/// User info returned by `GET /auth/me`.
#[derive(Debug, Serialize)]
pub struct AuthMeResponse {
    /// OIDC subject identifier.
    pub sub: String,
    /// Email address.
    pub email: Option<String>,
    /// Display name (`name` claim, falling back to given + family name).
    pub name: Option<String>,
    /// Group memberships.
    pub groups: Vec<String>,
}

/// The connected BFF auth stack: OIDC client, session layer, CSRF layer.
///
/// Build with [`BffAuth::connect`], then wrap your application router with
/// [`BffAuth::attach`].
pub struct BffAuth<S: SessionStore> {
    /// The discovered axum-oidc client.
    oidc_client: OidcClient<GroupsClaims>,
    /// Signed-cookie session layer.
    session_layer: SessionManagerLayer<S, SignedCookie>,
    /// Cross-origin request rejection.
    csrf_layer: CsrfLayer,
    /// Where the provider redirects after an RP-initiated logout.
    post_logout_uri: Uri,
    /// Behavior options.
    opts: BffOptions,
}

impl<S: SessionStore + Clone> BffAuth<S> {
    /// Run OIDC discovery, build the OIDC client, and spawn the background
    /// rediscover task; assemble session and CSRF layers.
    ///
    /// `public_url` is the service's own public base URL (no trailing
    /// slash needed): it derives the OIDC redirect URL
    /// (`{public_url}/auth/callback`), the post-logout redirect, and the
    /// CSRF trusted origin. Run any store migration (e.g.
    /// `SqliteStore::migrate`) before passing `session_store` in.
    pub async fn connect(
        config: &BffConfig,
        public_url: &str,
        session_store: S,
        signing_key: Key,
        opts: BffOptions,
    ) -> Result<Self, BffError> {
        // Preflight discovery so we hand the *advertised* issuer to
        // `.discover()`, which enforces byte-for-byte issuer equality.
        let issuer = IssuerUrl::new(discovered_issuer(config.issuer.as_str()).await?)?;

        let public_url = public_url.trim_end_matches('/');
        let redirect_url: Uri = format!("{public_url}/auth/callback").parse()?;
        let post_logout_uri: Uri = public_url.parse()?;

        let mut builder = OidcClient::<GroupsClaims>::builder()
            .with_default_http_client()
            .with_redirect_url(redirect_url)
            .with_client_id(config.client_id.clone())
            .with_client_secret(config.client_secret.clone());
        for scope in &opts.scopes {
            builder = builder.add_scope(Scope::new(scope.clone()));
        }
        let oidc_client = builder.discover(issuer.clone()).await?.build();

        spawn_rediscover_task(
            oidc_client.clone(),
            issuer,
            config.discovery_refresh_interval_seconds,
        );

        let session_layer = build_session_layer(
            session_store,
            signing_key,
            opts.cookie_name,
            opts.secure_cookies,
        );
        let csrf_layer = build_csrf_layer(public_url);

        Ok(Self {
            oidc_client,
            session_layer,
            csrf_layer,
            post_logout_uri,
            opts,
        })
    }

    /// Wrap `protected` with the auth stack and mount the `/auth/*` routes.
    ///
    /// Routes and layers, outermost first: CSRF, sessions, `/auth/clear`,
    /// OIDC auth (populates claims; returns 401 via handlers/gate, no
    /// redirect), then `/auth/login`+`/auth/logout` (these force a login),
    /// `/auth/me`, `/auth/callback`, and your `protected` routes.
    ///
    /// Add app-specific outer layers (tracing, compression, body limits) and
    /// fallbacks (static files) on the returned router.
    pub fn attach<St: Clone + Send + Sync + 'static>(self, protected: Router<St>) -> Router<St> {
        let Self {
            oidc_client,
            session_layer,
            csrf_layer,
            post_logout_uri,
            opts,
        } = self;

        let oidc_login_service = ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|e: MiddlewareError| async move {
                tracing::error!(?e, "error in OIDC login middleware");
                e.into_response()
            }))
            .layer(OidcLoginLayer::<GroupsClaims, OidcSessionStore>::new());

        let oidc_auth_service = ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|e: MiddlewareError| async move {
                tracing::error!(?e, "error in OIDC auth middleware");
                e.into_response()
            }))
            .layer(OidcAuthLayer::<GroupsClaims, OidcSessionStore>::new(
                oidc_client,
            ));

        // Routes that force a login (redirect to the provider when needed).
        let post_login_redirect = opts.post_login_redirect;
        let auth_routes = Router::new()
            .route(
                "/auth/login",
                get(move || async move { Redirect::to(&post_login_redirect) }),
            )
            .route(
                "/auth/logout",
                get(move |logout: OidcRpInitiatedLogout| async move {
                    logout
                        .with_post_logout_redirect(post_logout_uri)
                        .into_response()
                }),
            )
            .layer(oidc_login_service);

        // OIDC callback (outside the login layer). A failed sign-in surfaces
        // as a bare 500 from `handle_oidc_redirect`; the recovery middleware
        // rewrites it into a session-flushing redirect.
        let callback_error_redirect = opts.callback_error_redirect;
        let oidc_callback = Router::new()
            .route(
                "/auth/callback",
                any(handle_oidc_redirect::<GroupsClaims, OidcSessionStore>),
            )
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let redirect_to = callback_error_redirect.clone();
                async move { recover_oidc_callback_error(req, next, &redirect_to).await }
            }));

        // Session clear endpoint (outside the OIDC layers so it works even
        // with a corrupt session).
        let session_routes = Router::new().route("/auth/clear", get(auth_clear_session));

        // /auth/me returns 401/403 instead of redirecting.
        let me_group = opts.require_group.clone();
        let me_route = get(move |claims: Option<OidcClaims<GroupsClaims>>| {
            let group = me_group.clone();
            async move { auth_me(claims, group.as_deref()) }
        });

        // Optional group gate over all protected routes.
        let protected = match opts.require_group {
            Some(group) => protected.layer(middleware::from_fn(
                move |claims: Option<OidcClaims<GroupsClaims>>, req: Request, next: Next| {
                    let group = group.clone();
                    async move {
                        match check_group(claims.as_ref(), Some(&group)) {
                            Ok(()) => next.run(req).await,
                            Err(status) => status.into_response(),
                        }
                    }
                },
            )),
            None => protected,
        };

        Router::new()
            .merge(auth_routes)
            .route("/auth/me", me_route)
            .merge(protected)
            .merge(oidc_callback)
            .layer(oidc_auth_service)
            .merge(session_routes)
            .layer(session_layer)
            // CSRF: reject cross-origin mutating requests (Sec-Fetch-Site / Origin).
            .layer(csrf_layer)
    }
}

/// 401 without a session, 403 when `group` is set and not held.
fn check_group(
    claims: Option<&OidcClaims<GroupsClaims>>,
    group: Option<&str>,
) -> Result<(), StatusCode> {
    let claims = claims.ok_or(StatusCode::UNAUTHORIZED)?;
    match group {
        Some(group) if !claims.additional_claims().has_group(group) => Err(StatusCode::FORBIDDEN),
        _ => Ok(()),
    }
}

/// Handler for `GET /auth/me`.
fn auth_me(
    claims: Option<OidcClaims<GroupsClaims>>,
    require_group: Option<&str>,
) -> Result<Json<AuthMeResponse>, StatusCode> {
    check_group(claims.as_ref(), require_group)?;
    let claims = claims.expect("checked by check_group");

    // Display name with fallback: name, then given_name + family_name.
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.to_string())
        .or_else(|| {
            let given = claims
                .given_name()
                .and_then(|g| g.get(None))
                .map(|s| s.to_string());
            let family = claims
                .family_name()
                .and_then(|f| f.get(None))
                .map(|s| s.to_string());
            match (given, family) {
                (Some(g), Some(f)) => Some(format!("{g} {f}")),
                (Some(g), None) => Some(g),
                (None, Some(f)) => Some(f),
                (None, None) => None,
            }
        });

    Ok(Json(AuthMeResponse {
        sub: claims.subject().to_string(),
        email: claims.email().map(|e| e.to_string()),
        name,
        groups: claims.additional_claims().groups.clone(),
    }))
}

/// Handler for `GET /auth/clear`: flush the session and restart the flow.
async fn auth_clear_session(session: Session) -> impl IntoResponse {
    session.flush().await.ok();
    Redirect::to("/auth/login")
}

/// Rewrite a failed OIDC callback into a session-flushing redirect.
///
/// `handle_oidc_redirect` renders its errors as a bare 500 that bypasses
/// `HandleErrorLayer` (stale auth code, PKCE/state mismatch, etc.). Without
/// this the user sees a raw "internal server error" and, with the broken
/// session still set, retrying loops.
async fn recover_oidc_callback_error(req: Request, next: Next, redirect_to: &str) -> Response {
    // Log the path only: the callback query string carries the single-use
    // auth code.
    let path = req.uri().path().to_owned();
    // Grab the session handle before the body is consumed. Flushing (not a
    // hand-rolled removal cookie) is required: rewriting the 500 to a
    // redirect re-enables the session layer's save path, which would
    // re-persist the still-populated pending session and override any manual
    // clear. Emptying it makes the layer emit the removal cookie itself.
    let session = req.extensions().get::<Session>().cloned();
    let response = next.run(req).await;

    if !response.status().is_server_error() {
        return response;
    }

    if let Some(session) = session {
        session.flush().await.ok();
    }
    tracing::warn!(
        path,
        status = %response.status(),
        "OIDC callback failed; clearing session and redirecting to {redirect_to}"
    );
    Redirect::to(redirect_to).into_response()
}
