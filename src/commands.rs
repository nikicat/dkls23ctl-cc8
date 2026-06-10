//! Subcommand implementations.

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use derivation_path::DerivationPath;
use rand::RngCore;
use tracing::info;

use sl_dkls23::{
    keygen::{self, Keyshare},
    setup::{
        keygen::SetupMessage as KeygenSetup, sign::SetupMessage as SignSetup, NoSigningKey,
        NoVerifyingKey,
    },
    sign, Seed,
};

use crate::{
    crypto, ids, session,
    storage::{self, KeyKind, StoredKey},
};

/// Grace period after quorum so all peers converge on the same participant set.
const SETTLE: Duration = Duration::from_secs(3);
/// Message TTL inside the relay store (also bounds how long a round waits).
const MSG_TTL: Duration = Duration::from_secs(90);

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn fresh_seed() -> Seed {
    let mut seed: Seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// mDNS service name: hardcoded tool id + operation + a fingerprint of the
/// session-binding parameters (so only peers in the same session find each other).
fn service_name(op: &str, parts: &[&[u8]]) -> String {
    let mut data = Vec::new();
    for p in parts {
        data.extend_from_slice(&(p.len() as u64).to_le_bytes());
        data.extend_from_slice(p);
    }
    format!("dkls23ctl-{op}-{}", ids::short_fingerprint(&data, 8))
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

pub async fn keygen(
    t: u8,
    n: u8,
    peer_id: &str,
    key_id: &str,
    timeout: Duration,
) -> Result<()> {
    if storage::exists(key_id, peer_id) {
        bail!(
            "a share for key_id='{key_id}' peer_id='{peer_id}' already exists at {}",
            storage::path_for(key_id, peer_id).display()
        );
    }

    if t == 1 {
        if n != 1 {
            bail!("t=1 is the singleton (plain key) case and requires n=1 (got n={n})");
        }
        return keygen_singleton(peer_id, key_id);
    }

    if t < 2 || n < t {
        bail!("invalid parameters: need 2 <= t <= n (got t={t}, n={n})");
    }

    let n = n as usize;
    let t = t as usize;

    let svc = service_name("kg", &[key_id.as_bytes(), &[t as u8], &[n as u8]]);
    info!("keygen {t}-of-{n} key_id='{key_id}' as peer '{peer_id}' (service {svc})");
    info!("waiting for {n} peers to start keygen for this key_id...");

    let session = session::establish(&svc, peer_id, None, n, SETTLE, timeout).await?;

    // Build the agreed committee ordering (sorted by user peer id).
    let mut committee: Vec<(String, iroh::EndpointId)> =
        vec![(peer_id.to_string(), session.my_eid)];
    for p in &session.peers {
        committee.push((p.user_peer_id.clone(), p.endpoint_id));
    }
    committee.sort_by(|a, b| a.0.cmp(&b.0));
    committee.dedup_by(|a, b| a.0 == b.0);

    if committee.len() != n {
        bail!(
            "expected exactly {n} peers but found {} (peer-ids: {:?})",
            committee.len(),
            committee.iter().map(|c| &c.0).collect::<Vec<_>>()
        );
    }
    let participants: Vec<String> = committee.iter().map(|c| c.0.clone()).collect();
    let my_index = participants
        .iter()
        .position(|p| p == peer_id)
        .ok_or_else(|| anyhow!("internal: self not in committee"))?;
    info!("committee: {participants:?}; my party index = {my_index}");

    let instance = ids::instance_id(
        "dkls23ctl/keygen/v1",
        &[
            key_id.as_bytes(),
            &[t as u8, n as u8],
            participants.join(",").as_bytes(),
        ],
    );

    let vks: Vec<NoVerifyingKey> = (0..n).map(NoVerifyingKey::new).collect();
    let ranks = vec![0u8; n];
    let setup = KeygenSetup::new(instance, NoSigningKey, my_index, vks, &ranks, t).with_ttl(MSG_TTL);

    info!("running distributed key generation...");
    let keyshare = tokio::time::timeout(timeout, keygen::run(setup, fresh_seed(), session.relay))
        .await
        .map_err(|_| anyhow!("keygen timed out (a peer may have gone offline)"))?
        .map_err(|e| anyhow!("keygen protocol failed: {e:?}"))?;

    let pubkey = crypto::point_to_hex(&keyshare.public_key());
    let stored = StoredKey {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        kind: KeyKind::Tss,
        t: t as u8,
        n: n as u8,
        party_index: my_index as u8,
        participants,
        public_key: pubkey.clone(),
        root_chain_code: hex::encode(keyshare.root_chain_code()),
        keyshare_b64: Some(b64().encode(keyshare.as_slice())),
        secret_hex: None,
    };
    let path = stored.save()?;
    info!("key share saved to {}", path.display());

    println!("{pubkey}");
    Ok(())
}

fn keygen_singleton(peer_id: &str, key_id: &str) -> Result<()> {
    info!("generating singleton (t=1) ECDSA key for key_id='{key_id}'");
    let key = crypto::generate_singleton();
    let mut chain_code = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut chain_code);

    let stored = StoredKey {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        kind: KeyKind::Singleton,
        t: 1,
        n: 1,
        party_index: 0,
        participants: vec![peer_id.to_string()],
        public_key: key.public_key_hex.clone(),
        root_chain_code: hex::encode(chain_code),
        keyshare_b64: None,
        secret_hex: Some(hex::encode(key.secret)),
    };
    let path = stored.save()?;
    info!("singleton key saved to {}", path.display());
    println!("{}", key.public_key_hex);
    Ok(())
}

// ---------------------------------------------------------------------------
// pubkey
// ---------------------------------------------------------------------------

pub fn pubkey(key_id: &str) -> Result<()> {
    let key = storage::load_any(key_id)?;
    println!("{}", key.public_key);
    Ok(())
}

// ---------------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------------

pub async fn sign(key_id: &str, peer_id: &str, msg: &str, timeout: Duration) -> Result<()> {
    let stored = storage::load(key_id, peer_id)?;

    if stored.kind == KeyKind::Singleton {
        let secret = parse_secret(&stored)?;
        let sig = crypto::singleton_sign(&secret, msg.as_bytes())?;
        info!("signed locally with singleton key");
        println!("{sig}");
        return Ok(());
    }

    let t = stored.t as usize;
    let my_party_id = stored.party_index;
    let keyshare = load_keyshare(&stored)?;

    let msg_hash = crypto::hash_message(msg.as_bytes());
    let svc = service_name("sg", &[key_id.as_bytes(), &msg_hash]);
    info!(
        "sign key_id='{key_id}' as peer '{peer_id}' (party {my_party_id}); need {t} signers (service {svc})"
    );
    info!("message hash: {}", hex::encode(msg_hash));
    info!("waiting for at least {t} peers to sign the same message...");

    let session = session::establish(
        &svc,
        peer_id,
        Some(my_party_id.to_string()),
        t,
        SETTLE,
        timeout,
    )
    .await?;

    // Signing quorum = every present signer, ordered by keyshare party id.
    let mut quorum: Vec<u8> = vec![my_party_id];
    for p in &session.peers {
        let pid: u8 = p
            .extra
            .as_deref()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("peer '{}' did not advertise its party id", p.user_peer_id))?;
        quorum.push(pid);
    }
    quorum.sort_unstable();
    quorum.dedup();
    if quorum.len() < t {
        bail!("not enough distinct signers: have {}, need {t}", quorum.len());
    }
    let my_idx = quorum
        .iter()
        .position(|&p| p == my_party_id)
        .ok_or_else(|| anyhow!("internal: self not in quorum"))?;
    info!("signing quorum (party ids): {quorum:?}; my index = {my_idx}");

    let quorum_bytes: Vec<u8> = quorum.clone();
    let instance = ids::instance_id(
        "dkls23ctl/sign/v1",
        &[key_id.as_bytes(), &msg_hash, &quorum_bytes],
    );

    let vks: Vec<NoVerifyingKey> = quorum
        .iter()
        .map(|&pid| NoVerifyingKey::new(pid as usize))
        .collect();
    let setup = SignSetup::new(instance, NoSigningKey, my_idx, vks, Arc::new(keyshare))
        .with_chain_path(DerivationPath::from_str("m").unwrap())
        .with_hash(msg_hash)
        .with_ttl(MSG_TTL);

    info!("running distributed signature generation...");
    let (signature, _recid) =
        tokio::time::timeout(timeout, sign::run(setup, fresh_seed(), session.relay))
            .await
            .map_err(|_| anyhow!("signing timed out (a peer may have gone offline)"))?
            .map_err(|e| anyhow!("signing protocol failed: {e:?}"))?;

    let sig_hex = crypto::signature_to_hex(&signature);
    // Local sanity check against the stored public key.
    match crypto::verify(&stored.public_key, msg.as_bytes(), &sig_hex) {
        Ok(true) => info!("signature verified against public key"),
        Ok(false) => bail!("produced signature failed verification (internal error)"),
        Err(e) => info!("could not self-verify signature: {e}"),
    }
    println!("{sig_hex}");
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

pub fn verify(key_id: &str, msg: &str, signature: &str) -> Result<()> {
    let key = storage::load_any(key_id)?;
    let ok = crypto::verify(&key.public_key, msg.as_bytes(), signature)?;
    if ok {
        println!("OK: valid signature");
        Ok(())
    } else {
        println!("FAIL: invalid signature");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn load_keyshare(stored: &StoredKey) -> Result<Keyshare> {
    let encoded = stored
        .keyshare_b64
        .as_ref()
        .ok_or_else(|| anyhow!("stored key has no TSS share data"))?;
    let bytes = b64().decode(encoded).context("decoding keyshare base64")?;
    Keyshare::from_bytes(&bytes).ok_or_else(|| anyhow!("stored keyshare is corrupt"))
}

fn parse_secret(stored: &StoredKey) -> Result<[u8; 32]> {
    let hexs = stored
        .secret_hex
        .as_ref()
        .ok_or_else(|| anyhow!("stored singleton key has no secret"))?;
    let bytes = hex::decode(hexs).context("decoding secret hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("secret is not 32 bytes"))?;
    Ok(arr)
}
