//! Reverse proxy helpers for forwarding requests to a backend API with the
//! session's bearer token (BFF pattern).

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::Response,
};
use axum_oidc::OidcAccessToken;
use tracing::warn;

/// Maximum request body size (20 MiB).
pub const CONTENT_LENGTH_LIMIT: usize = 20 * 1024 * 1024;

/// Forward a request to the backend, injecting the Bearer token.
///
/// Only the `Content-Type` header is forwarded from the incoming request.
pub async fn send_proxy_request(
    http_client: &reqwest::Client,
    parts: &axum::http::request::Parts,
    body: Body,
    target_url: &str,
    access_token: &OidcAccessToken,
) -> Result<reqwest::Response, StatusCode> {
    // Buffer the entire incoming body (up to CONTENT_LENGTH_LIMIT) before forwarding
    let body_bytes = axum::body::to_bytes(body, CONTENT_LENGTH_LIMIT)
        .await
        .map_err(|e| {
            warn!("Failed to read request body: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    // Build outbound request: same method/URL, but only forward Authorization and Content-Type
    let mut req = http_client
        .request(parts.method.clone(), target_url)
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token.0));

    if let Some(content_type) = parts.headers.get(header::CONTENT_TYPE) {
        req = req.header(header::CONTENT_TYPE, content_type.clone());
    }

    if !body_bytes.is_empty() {
        req = req.body(body_bytes);
    }

    req.send().await.map_err(|e| {
        warn!("Proxy request failed: {}", e);
        StatusCode::BAD_GATEWAY
    })
}

/// Convert a reqwest response into an axum response, forwarding headers.
pub async fn build_proxy_response(response: reqwest::Response) -> Result<Response, StatusCode> {
    let status = response.status();
    let headers = response.headers().clone();

    let body_bytes = response.bytes().await.map_err(|e| {
        warn!("Failed to read proxy response body: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    let mut builder = Response::builder().status(status.as_u16());

    // Forward all response headers except hop-by-hop headers
    for (name, value) in headers.iter() {
        if name == header::TRANSFER_ENCODING || name == header::CONNECTION {
            continue;
        }
        builder = builder.header(name, value);
    }

    builder
        .body(Body::from(body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
