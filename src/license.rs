//! Offline Pro license keys (ed25519). No Kiket billing federation.
//!
//! Format: `mr1.<base64url(payload_json)>.<base64url(signature)>`
//! Payload: `{"v":1,"tier":"pro","sub":"<org/repo or *>","exp":<unix|null>}`

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// mayrun.dev Pro verifying key (32-byte hex). Override with `MAYRUN_LICENSE_PUBLIC_KEY`.
///
/// Matching dogfood signing key is documented in `docs/license.md` (rotate before live Stripe).
pub const DEFAULT_VERIFYING_KEY_HEX: &str =
    "2b8279b253b5bdb10ad2878064bdd1c2f6972223cf7f5f55fb1ef73e3dbd31dd";

/// Dogfood signing key hex (tests + local demos). Prefer `MAYRUN_LICENSE_SIGNING_KEY` in prod.
pub const DOGFOOD_SIGNING_KEY_HEX: &str =
    "8f299830a44a60a84ac7f0b1dd475d3b50b0a9822675e877a6f08e2af9cb0717";

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("invalid license format")]
    Format,
    #[error("invalid license payload: {0}")]
    Payload(String),
    #[error("invalid signature")]
    Signature,
    #[error("license expired")]
    Expired,
    #[error("license subject mismatch (got {got}, need {need})")]
    Subject { got: String, need: String },
    #[error("not a Pro license (tier={0})")]
    Tier(String),
    #[error("bad key material: {0}")]
    Key(String),
    #[error("signing key required (set MAYRUN_LICENSE_SIGNING_KEY hex)")]
    MissingSigningKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    pub v: u32,
    pub tier: String,
    /// Repository slug (`owner/repo`) or `*` for any.
    pub sub: String,
    /// Unix expiry seconds; omit / null = no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedLicense {
    pub payload: LicensePayload,
}

fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, LicenseError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| LicenseError::Format)
}

fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey, LicenseError> {
    let bytes = hex::decode(hex_key.trim()).map_err(|e| LicenseError::Key(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(LicenseError::Key(format!(
            "expected 32-byte verifying key, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| LicenseError::Key(e.to_string()))
}

fn parse_signing_key(hex_key: &str) -> Result<SigningKey, LicenseError> {
    let bytes = hex::decode(hex_key.trim()).map_err(|e| LicenseError::Key(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(LicenseError::Key(format!(
            "expected 32-byte signing key, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

pub fn resolving_verifying_key() -> Result<VerifyingKey, LicenseError> {
    if let Ok(hex_key) = std::env::var("MAYRUN_LICENSE_PUBLIC_KEY") {
        if !hex_key.trim().is_empty() {
            return parse_verifying_key(&hex_key);
        }
    }
    parse_verifying_key(DEFAULT_VERIFYING_KEY_HEX)
}

/// Mint a signed Pro license. Requires `MAYRUN_LICENSE_SIGNING_KEY` (32-byte hex).
pub fn mint(sub: &str, exp: Option<u64>) -> Result<String, LicenseError> {
    let hex_key = std::env::var("MAYRUN_LICENSE_SIGNING_KEY")
        .map_err(|_| LicenseError::MissingSigningKey)?;
    mint_with_key(&hex_key, sub, exp)
}

pub fn mint_with_key(signing_key_hex: &str, sub: &str, exp: Option<u64>) -> Result<String, LicenseError> {
    let signing = parse_signing_key(signing_key_hex)?;
    let payload = LicensePayload {
        v: 1,
        tier: "pro".into(),
        sub: sub.to_string(),
        exp,
    };
    let payload_json =
        serde_json::to_vec(&payload).map_err(|e| LicenseError::Payload(e.to_string()))?;
    let sig = signing.sign(&payload_json);
    Ok(format!(
        "mr1.{}.{}",
        b64_encode(&payload_json),
        b64_encode(&sig.to_bytes())
    ))
}

pub fn verify(
    license: &str,
    expected_sub: Option<&str>,
    now_unix: Option<u64>,
) -> Result<VerifiedLicense, LicenseError> {
    verify_with_key(&resolving_verifying_key()?, license, expected_sub, now_unix)
}

pub fn verify_with_key(
    verifying: &VerifyingKey,
    license: &str,
    expected_sub: Option<&str>,
    now_unix: Option<u64>,
) -> Result<VerifiedLicense, LicenseError> {
    let license = license.trim();
    let mut parts = license.split('.');
    let prefix = parts.next().ok_or(LicenseError::Format)?;
    let payload_b64 = parts.next().ok_or(LicenseError::Format)?;
    let sig_b64 = parts.next().ok_or(LicenseError::Format)?;
    if parts.next().is_some() || prefix != "mr1" {
        return Err(LicenseError::Format);
    }
    let payload_bytes = b64_decode(payload_b64)?;
    let sig_bytes = b64_decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err(LicenseError::Signature);
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    verifying
        .verify(&payload_bytes, &signature)
        .map_err(|_| LicenseError::Signature)?;

    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LicenseError::Payload(e.to_string()))?;
    if payload.v != 1 {
        return Err(LicenseError::Payload(format!("unsupported v={}", payload.v)));
    }
    if payload.tier != "pro" {
        return Err(LicenseError::Tier(payload.tier));
    }
    let now = now_unix.unwrap_or_else(unix_now);
    if let Some(exp) = payload.exp {
        if now > exp {
            return Err(LicenseError::Expired);
        }
    }
    if let Some(need) = expected_sub {
        if payload.sub != "*" && payload.sub != need {
            return Err(LicenseError::Subject {
                got: payload.sub,
                need: need.to_string(),
            });
        }
    }
    Ok(VerifiedLicense { payload })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Derive verifying key hex from a signing key hex (for operator runbooks).
pub fn verifying_key_hex_from_signing(signing_key_hex: &str) -> Result<String, LicenseError> {
    let signing = parse_signing_key(signing_key_hex)?;
    Ok(hex::encode(signing.verifying_key().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (String, String) {
        // Fixed test key — not the DEFAULT_VERIFYING_KEY (which is a placeholder).
        let sk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let vk = verifying_key_hex_from_signing(sk).unwrap();
        (sk.to_string(), vk)
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let (sk, vk) = test_keypair();
        let key = mint_with_key(&sk, "kiket-dev/mayrun", None).unwrap();
        assert!(key.starts_with("mr1."));
        let verifying = parse_verifying_key(&vk).unwrap();
        let verified =
            verify_with_key(&verifying, &key, Some("kiket-dev/mayrun"), None).unwrap();
        assert_eq!(verified.payload.tier, "pro");
        assert_eq!(verified.payload.sub, "kiket-dev/mayrun");
    }

    #[test]
    fn wildcard_sub_matches_any() {
        let (sk, vk) = test_keypair();
        let key = mint_with_key(&sk, "*", None).unwrap();
        let verifying = parse_verifying_key(&vk).unwrap();
        verify_with_key(&verifying, &key, Some("any/repo"), None).unwrap();
    }

    #[test]
    fn expired_rejected() {
        let (sk, vk) = test_keypair();
        let key = mint_with_key(&sk, "*", Some(1)).unwrap();
        let verifying = parse_verifying_key(&vk).unwrap();
        let err = verify_with_key(&verifying, &key, None, Some(100)).unwrap_err();
        assert!(matches!(err, LicenseError::Expired));
    }

    #[test]
    fn tampered_payload_fails() {
        let (sk, vk) = test_keypair();
        let key = mint_with_key(&sk, "a/b", None).unwrap();
        let parts: Vec<_> = key.split('.').collect();
        let mut payload = b64_decode(parts[1]).unwrap();
        if let Some(b) = payload.last_mut() {
            *b ^= 0xff;
        }
        let bad = format!("mr1.{}.{}", b64_encode(&payload), parts[2]);
        let verifying = parse_verifying_key(&vk).unwrap();
        assert!(verify_with_key(&verifying, &bad, None, None).is_err());
    }
}
