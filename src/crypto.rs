//! Cryptographic helpers: message hashing, public-key formatting, signature
//! verification, and standalone (singleton) ECDSA key generation / signing.
//!
//! Everything uses the `k256` re-exported by `sl-dkls23` so the curve types line
//! up exactly with the threshold engine (no risk of two incompatible `k256`s).

use anyhow::{anyhow, Result};
use sl_dkls23::k256::{
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{group::GroupEncoding, sec1::ToEncodedPoint},
    ProjectivePoint, SecretKey,
};
use sha2::{Digest, Sha256};

/// Hash a message down to the 32-byte prehash that ECDSA actually signs.
/// We use SHA-256 of the raw message bytes.
pub fn hash_message(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg);
    h.finalize().into()
}

/// Compressed SEC1 hex (33 bytes -> 66 hex chars) of a curve point.
pub fn point_to_hex(pk: &ProjectivePoint) -> String {
    hex::encode(pk.to_bytes())
}

/// Parse a compressed/uncompressed SEC1 public key hex into a `VerifyingKey`.
pub fn verifying_key_from_hex(pubkey_hex: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(pubkey_hex.trim()).map_err(|e| anyhow!("bad pubkey hex: {e}"))?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|e| anyhow!("invalid public key: {e}"))
}

/// Parse a SEC1 public key hex into a curve point (for reshare's expected key).
pub fn pubkey_hex_to_point(pubkey_hex: &str) -> Result<ProjectivePoint> {
    let vk = verifying_key_from_hex(pubkey_hex)?;
    Ok((*vk.as_affine()).into())
}

/// Verify a compact (r||s, 64-byte) signature over `msg` for the given
/// compressed-SEC1 public key hex. Hashing is applied internally.
pub fn verify(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<bool> {
    let vk = verifying_key_from_hex(pubkey_hex)?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|e| anyhow!("bad signature hex: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("invalid signature encoding: {e}"))?;
    let hash = hash_message(msg);
    Ok(vk.verify_prehash(&hash, &sig).is_ok())
}

/// Encode a finished signature as compact r||s hex.
pub fn signature_to_hex(sig: &Signature) -> String {
    hex::encode(sig.to_bytes())
}

/// A freshly generated standalone (t=1) ECDSA secp256k1 key.
pub struct SingletonKey {
    /// 32-byte big-endian secret scalar.
    pub secret: [u8; 32],
    /// Compressed SEC1 public key hex.
    pub public_key_hex: String,
}

/// Generate a plain ECDSA private key (used for the t=1 "singleton" case).
pub fn generate_singleton() -> SingletonKey {
    let sk = SecretKey::random(&mut rand::rngs::OsRng);
    let secret: [u8; 32] = sk.to_bytes().into();
    let pk = sk.public_key();
    let public_key_hex = hex::encode(pk.to_encoded_point(true).as_bytes());
    SingletonKey {
        secret,
        public_key_hex,
    }
}

/// Compressed-SEC1 public key hex for a raw 32-byte secret scalar.
pub fn singleton_public_key_hex(secret: &[u8; 32]) -> Result<String> {
    let sk = SecretKey::from_slice(secret).map_err(|e| anyhow!("invalid secret: {e}"))?;
    Ok(hex::encode(sk.public_key().to_encoded_point(true).as_bytes()))
}

/// Sign `msg` with a standalone secret key (t=1). Hashing is applied internally.
/// Returns the compact r||s hex signature.
pub fn singleton_sign(secret: &[u8; 32], msg: &[u8]) -> Result<String> {
    let signing = SigningKey::from_slice(secret).map_err(|e| anyhow!("invalid secret: {e}"))?;
    let hash = hash_message(msg);
    let sig: Signature = signing
        .sign_prehash(&hash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    Ok(signature_to_hex(&sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singleton_sign_verify_roundtrip() {
        let key = generate_singleton();
        let msg = b"hello threshold world";
        let sig = singleton_sign(&key.secret, msg).unwrap();

        assert!(verify(&key.public_key_hex, msg, &sig).unwrap());
        // Tampered message must not verify.
        assert!(!verify(&key.public_key_hex, b"goodbye", &sig).unwrap());
    }

    #[test]
    fn pubkey_derivation_is_stable() {
        let key = generate_singleton();
        let derived = singleton_public_key_hex(&key.secret).unwrap();
        assert_eq!(derived, key.public_key_hex);
    }

    #[test]
    fn pubkey_hex_to_point_roundtrips() {
        let key = generate_singleton();
        let pt = pubkey_hex_to_point(&key.public_key_hex).unwrap();
        assert_eq!(point_to_hex(&pt), key.public_key_hex);
    }
}
