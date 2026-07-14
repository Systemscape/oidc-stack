//! HMAC-SHA256 signed-request primitive for inter-service authentication.
//!
//! Recipe: signature is the hex-encoded HMAC-SHA256 of `{timestamp}.{body}`
//! using a shared secret. The signer (e.g. a BFF) calls [`sign`]; the
//! verifier (e.g. an internal API endpoint) calls [`verify`].
//!
//! Replay window: +/-[`MAX_SKEW_SECS`] seconds. Comparison is constant-time.
//!
//! Header-presence errors (missing timestamp/signature header) are an
//! HTTP-layer concern and intentionally not modelled here; callers handle
//! their own header extraction.

use chrono::Utc;
use hmac::{Hmac, KeyInit as _, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Maximum allowed clock skew between signer and verifier, in seconds.
pub const MAX_SKEW_SECS: i64 = 300;

/// Errors returned by [`verify`].
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
pub enum SignedRequestError {
    #[error("Timestamp is not a valid integer")]
    BadTimestamp,
    #[error("Request timestamp is outside the allowed skew window")]
    Stale,
    #[error("Signature is not valid hex")]
    BadSignatureEncoding,
    #[error("Signature mismatch")]
    SignatureMismatch,
}

/// Sign `{timestamp}.{body}` with `secret`, returning the hex-encoded
/// HMAC-SHA256 digest.
pub fn sign(secret: &SecretString, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify a hex-encoded HMAC-SHA256 signature over `{timestamp}.{body}`
/// against `secret`, enforcing a +/-[`MAX_SKEW_SECS`] window on the
/// timestamp.
pub fn verify(
    secret: &SecretString,
    timestamp: &str,
    body: &[u8],
    sig_hex: &str,
) -> Result<(), SignedRequestError> {
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| SignedRequestError::BadTimestamp)?;
    let now = Utc::now().timestamp();
    if (now - ts).abs() > MAX_SKEW_SECS {
        return Err(SignedRequestError::Stale);
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    let provided = hex::decode(sig_hex).map_err(|_| SignedRequestError::BadSignatureEncoding)?;
    if expected.as_slice().ct_eq(&provided).into() {
        Ok(())
    } else {
        Err(SignedRequestError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_round_trip() {
        let secret = SecretString::from("topsecret");
        let body = br#"{"email":"a@b.c"}"#;
        let ts = Utc::now().timestamp().to_string();
        let sig = sign(&secret, &ts, body);
        assert!(verify(&secret, &ts, body, &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_signature() {
        let signer = SecretString::from("wrong-secret");
        let verifier = SecretString::from("topsecret");
        let body = br#"{"email":"a@b.c"}"#;
        let ts = Utc::now().timestamp().to_string();
        let sig = sign(&signer, &ts, body);
        assert!(matches!(
            verify(&verifier, &ts, body, &sig),
            Err(SignedRequestError::SignatureMismatch)
        ));
    }

    #[test]
    fn rejects_tampered_body() {
        let secret = SecretString::from("topsecret");
        let body = br#"{"email":"a@b.c"}"#;
        let ts = Utc::now().timestamp().to_string();
        let sig = sign(&secret, &ts, body);
        let tampered = br#"{"email":"x@b.c"}"#;
        assert!(matches!(
            verify(&secret, &ts, tampered, &sig),
            Err(SignedRequestError::SignatureMismatch)
        ));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let secret = SecretString::from("topsecret");
        let body = br#"{"email":"a@b.c"}"#;
        let ts = (Utc::now().timestamp() - 600).to_string();
        let sig = sign(&secret, &ts, body);
        assert!(matches!(
            verify(&secret, &ts, body, &sig),
            Err(SignedRequestError::Stale)
        ));
    }

    #[test]
    fn rejects_bad_hex() {
        let secret = SecretString::from("topsecret");
        let body = b"x";
        let ts = Utc::now().timestamp().to_string();
        assert!(matches!(
            verify(&secret, &ts, body, "not-hex-zz"),
            Err(SignedRequestError::BadSignatureEncoding)
        ));
    }
}
