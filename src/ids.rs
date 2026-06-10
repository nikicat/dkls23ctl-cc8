//! Deterministic identifiers shared across peers.
//!
//! Because there is no leader, every peer must independently arrive at the same
//! protocol `InstanceId` and the same party ordering. We derive both from values
//! that all peers agree on (key id, parameters, the sorted committee, the message
//! being signed), so no negotiation round is needed.

use sha2::{Digest, Sha256};
use sl_dkls23::InstanceId;

/// Domain-separated hash of a list of byte parts.
fn tagged_hash(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Derive a protocol `InstanceId` deterministically. All participants that pass
/// identical `domain` + `parts` get the same id (and thus matching message ids).
pub fn instance_id(domain: &str, parts: &[&[u8]]) -> InstanceId {
    InstanceId::new(tagged_hash(domain, parts))
}

/// Short lowercase-hex fingerprint, used to build DNS-safe mDNS service names.
pub fn short_fingerprint(data: &[u8], bytes: usize) -> String {
    let h = tagged_hash("dkls23ctl/fp", &[data]);
    hex::encode(&h[..bytes.min(32)])
}
