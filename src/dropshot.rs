//! Bearer-token authentication for dropshot servers.
//!
//! Implement [`OidcAuth`] on your dropshot server context, then take
//! [`Authed<C>`] as a handler parameter to require a valid bearer token:
//!
//! ```ignore
//! impl OidcAuth for AppContext {
//!     type Identity = User;
//!     fn validator(&self) -> &TokenValidator { &self.validator }
//!     async fn resolve(&self, claims: Claims, _token: &str) -> Result<User, HttpError> {
//!         self.lookup_user(&claims.sub).await
//!     }
//! }
//!
//! #[endpoint { method = GET, path = "/me" }]
//! async fn me(rqctx: RequestContext<AppContext>, auth: Authed<AppContext>) -> ... {
//!     let user = auth.0;
//! }
//! ```

use std::future::Future;
use std::ops::Deref;

use async_trait::async_trait;
use dropshot::{
    ApiEndpointBodyContentType, ClientErrorStatusCode, ExtractorMetadata, Header, HttpError,
    RequestContext, ServerContext, SharedExtractor,
};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use crate::validator::{Claims, TokenValidator};

/// Hook implemented by the dropshot server context to enable [`Authed`].
pub trait OidcAuth: ServerContext + Sized {
    /// Authenticated identity produced by [`OidcAuth::resolve`], carried in
    /// [`Authed`].
    type Identity: Send + Sync + 'static;

    /// The token validator to check bearer tokens against.
    fn validator(&self) -> &TokenValidator;

    /// Map validated claims to the application identity. This is the policy
    /// hook: group checks, user lookup/provisioning, etc. The raw
    /// `access_token` is passed along for flows that need it (e.g. a
    /// userinfo request).
    fn resolve(
        &self,
        claims: Claims,
        access_token: &str,
    ) -> impl Future<Output = Result<Self::Identity, HttpError>> + Send;
}

/// Dropshot extractor that authenticates the request's bearer token.
///
/// Rejects with 401 when the `Authorization` header is missing or the token
/// does not validate; otherwise carries the identity produced by
/// [`OidcAuth::resolve`].
pub struct Authed<C: OidcAuth>(pub C::Identity);

/// Request headers carrying authentication information.
#[derive(Deserialize, JsonSchema)]
struct AuthHeaders {
    /// OIDC access token, with or without the `Bearer ` prefix.
    // Alias works around https://github.com/oxidecomputer/dropshot/issues/1373
    #[serde(rename = "Authorization", alias = "authorization")]
    authorization: Option<SecretString>,
}

/// 401 response shared by all rejection paths (details are logged, not leaked).
fn unauthorized() -> HttpError {
    HttpError::for_client_error(
        None,
        ClientErrorStatusCode::UNAUTHORIZED,
        "unauthorized".into(),
    )
}

#[async_trait]
impl<C: OidcAuth> SharedExtractor for Authed<C> {
    async fn from_request<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
    ) -> Result<Self, HttpError> {
        // Turn the generic context into the concrete one implementing OidcAuth.
        let Some(rqctx) = (rqctx as &dyn std::any::Any).downcast_ref::<RequestContext<C>>() else {
            return Err(HttpError::for_internal_error(
                "bad server context type".into(),
            ));
        };

        let headers = Header::<AuthHeaders>::from_request(rqctx)
            .await?
            .into_inner();
        let Some(authorization) = headers.authorization else {
            tracing::error!("No Authorization header provided");
            return Err(unauthorized());
        };

        let raw = authorization.expose_secret();
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .unwrap_or(raw);

        let claims = rqctx
            .context()
            .validator()
            .validate_token::<Claims>(token)
            .map_err(|e| {
                tracing::error!("OIDC token validation failed: {e}");
                unauthorized()
            })?;

        let identity = rqctx.context().resolve(claims, token).await?;
        Ok(Authed(identity))
    }

    fn metadata(body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata {
        Header::<AuthHeaders>::metadata(body_content_type)
    }
}

/// Wrapper for `SecretBox<str>` implementing the traits dropshot headers
/// need (`JsonSchema`, redacting `Serialize`).
#[derive(Deserialize)]
pub struct SecretString(SecretBox<str>);

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("[SECRET REDACTED]")
    }
}

impl Deref for SecretString {
    type Target = SecretBox<str>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl JsonSchema for SecretString {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "String".into()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: None,
            ..Default::default()
        }
        .into()
    }
}
