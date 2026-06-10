//! On-disk persistence of key shares and their generation parameters.
//!
//! Layout: `./.secrets/<key_id>/<peer_id>.json`. Each file holds this peer's
//! share plus enough metadata (t, n, the public key, the committee, the chain
//! code) to drive later sign / reshare operations without re-deriving anything.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Whether a stored key is a real threshold share or a plain (t=1) secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    /// DKLS23 threshold share (t >= 2).
    Tss,
    /// Plain ECDSA secret key (t = 1).
    Singleton,
}

/// A persisted key share with its parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub key_id: String,
    pub peer_id: String,
    pub kind: KeyKind,
    pub t: u8,
    pub n: u8,
    /// This peer's party index within the DKG committee (0..n). Unused for singletons.
    pub party_index: u8,
    /// The committee at generation time: sorted peer-id strings; position == party index.
    pub participants: Vec<String>,
    /// Compressed SEC1 public key, hex (same for every peer of a key_id).
    pub public_key: String,
    /// BIP32-style root chain code, hex (32 bytes). Needed for import/export reshare.
    pub root_chain_code: String,
    /// base64 of `Keyshare::as_slice()` for TSS shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyshare_b64: Option<String>,
    /// hex of the 32-byte secret scalar for singletons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_hex: Option<String>,
}

fn secrets_root() -> PathBuf {
    PathBuf::from("./.secrets")
}

fn key_dir(key_id: &str) -> PathBuf {
    secrets_root().join(key_id)
}

/// Absolute-ish path to a specific peer's share file.
pub fn path_for(key_id: &str, peer_id: &str) -> PathBuf {
    key_dir(key_id).join(format!("{peer_id}.json"))
}

impl StoredKey {
    /// Write this share to `./.secrets/<key_id>/<peer_id>.json` (creating dirs).
    pub fn save(&self) -> Result<PathBuf> {
        let dir = key_dir(&self.key_id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path = path_for(&self.key_id, &self.peer_id);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }
}

/// Load a specific peer's share.
pub fn load(key_id: &str, peer_id: &str) -> Result<StoredKey> {
    let path = path_for(key_id, peer_id);
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("no key share at {} — run keygen first", path.display()))?;
    let key: StoredKey = serde_json::from_str(&data)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(key)
}

/// Load any one share for a key_id (used by `pubkey`, which is peer-agnostic).
pub fn load_any(key_id: &str) -> Result<StoredKey> {
    let dir = key_dir(key_id);
    let rd = std::fs::read_dir(&dir)
        .with_context(|| format!("no shares for key_id '{key_id}' (looked in {})", dir.display()))?;
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let data = std::fs::read_to_string(&path)?;
            if let Ok(key) = serde_json::from_str::<StoredKey>(&data) {
                return Ok(key);
            }
        }
    }
    Err(anyhow!("no valid share files in {}", dir.display()))
}

/// True if this peer already has a share for the key_id.
pub fn exists(key_id: &str, peer_id: &str) -> bool {
    path_for(key_id, peer_id).exists()
}
