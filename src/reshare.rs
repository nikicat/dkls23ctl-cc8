//! `reshare`: change a key's (t, n) parameters while preserving its public key.
//!
//! Four cases are handled, dispatched on the *old* key kind and the *new*
//! threshold:
//!
//! | old \ new | t' >= 2 (TSS)            | t' = 1 (singleton)       |
//! |-----------|-------------------------|--------------------------|
//! | TSS       | quorum_change           | export (combine_shares)  |
//! | singleton | import (secret_shares)  | copy secret              |
//!
//! All peers running `reshare` for a key id discover each other over the same
//! mDNS service. Participants are ordered "old-holders first, then by peer id",
//! which matches the index convention DKLS23's quorum-change expects.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use tracing::info;

use iroh::EndpointId;
use sl_dkls23::{
    k256::{elliptic_curve::PrimeField, NonZeroScalar, Scalar},
    keygen::{
        key_refresh::{self, KeyshareForRefresh},
        quorum_change, Keyshare,
    },
    key_export::combine_shares,
    key_import::ecdsa_secret_shares,
    setup::{
        keygen::SetupMessage as KeygenSetup, quorum_change::SetupMessage as QcSetup, NoSigningKey,
        NoVerifyingKey,
    },
    Seed,
};

use crate::{
    crypto, ids,
    net::{self, Discovery, PeerInfo},
    storage::{self, KeyKind, StoredKey},
};

const SETTLE: Duration = Duration::from_secs(3);
const MSG_TTL: Duration = Duration::from_secs(120);

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn fresh_seed() -> Seed {
    let mut seed: Seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

fn service_name(key_id: &str, new_t: u8, new_n: u8) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(key_id.as_bytes());
    data.push(new_t);
    data.push(new_n);
    format!("dkls23ctl-rs-{}", ids::short_fingerprint(&data, 8))
}

/// What a peer advertises about itself over mDNS TXT.
#[derive(Clone)]
struct Descriptor {
    have: bool,
    old_t: u8,
    old_n: u8,
    old_kind: Option<KeyKind>,
    pubkey: String,
}

impl Descriptor {
    fn encode(&self) -> String {
        let kind = match self.old_kind {
            Some(KeyKind::Tss) => "tss",
            Some(KeyKind::Singleton) => "singleton",
            None => "none",
        };
        format!(
            "{}:{}:{}:{}:{}",
            if self.have { "have" } else { "new" },
            self.old_t,
            self.old_n,
            kind,
            self.pubkey
        )
    }

    fn decode(s: &str) -> Option<Descriptor> {
        let mut it = s.splitn(5, ':');
        let role = it.next()?;
        let old_t = it.next()?.parse().ok()?;
        let old_n = it.next()?.parse().ok()?;
        let kind = match it.next()? {
            "tss" => Some(KeyKind::Tss),
            "singleton" => Some(KeyKind::Singleton),
            _ => None,
        };
        let pubkey = it.next()?.to_string();
        Some(Descriptor {
            have: role == "have",
            old_t,
            old_n,
            old_kind: kind,
            pubkey,
        })
    }
}

/// A participant in the reshare protocol, in agreed order.
#[derive(Clone)]
struct Part {
    peer_id: String,
    eid: EndpointId,
    have: bool,
}

pub async fn run(peer_id: &str, key_id: &str, new_t: u8, new_n: u8, timeout: Duration) -> Result<()> {
    if new_t < 1 || new_n < new_t {
        bail!("invalid new parameters: need 1 <= t <= n (got t={new_t}, n={new_n})");
    }

    let existing = storage::load(key_id, peer_id).ok();
    let my_desc = match &existing {
        Some(k) => Descriptor {
            have: true,
            old_t: k.t,
            old_n: k.n,
            old_kind: Some(k.kind),
            pubkey: k.public_key.clone(),
        },
        None => Descriptor {
            have: false,
            old_t: 0,
            old_n: 0,
            old_kind: None,
            pubkey: String::new(),
        },
    };

    let svc = service_name(key_id, new_t, new_n);
    info!(
        "reshare key_id='{key_id}' to {new_t}-of-{new_n} as peer '{peer_id}' (have_share={}, service {svc})",
        my_desc.have
    );

    // Bind + discover.
    let (endpoint, lookup) = net::bind_endpoint().await?;
    let my_eid = endpoint.id();
    let port = net::endpoint_port(&endpoint)?;
    let ips = net::local_ipv4s();
    info!("this peer: endpoint={} udp_port={}", my_eid.fmt_short(), port);
    let discovery = Discovery::start(&svc, my_eid, peer_id, Some(my_desc.encode()), port, ips)?;

    // Adaptive wait: learn old parameters from any holder, then wait until we
    // have >= old_t holders and >= new_n participants total.
    let (_, old) = wait_for_reshare_quorum(&discovery, &my_desc, new_n, timeout).await?;
    tokio::time::sleep(SETTLE).await;
    let others = discovery.snapshot();

    // Build the agreed participant order: holders first, then by peer id.
    let mut parts: Vec<Part> = vec![Part {
        peer_id: peer_id.to_string(),
        eid: my_eid,
        have: my_desc.have,
    }];
    for p in &others {
        let have = Descriptor::decode(p.extra.as_deref().unwrap_or(""))
            .map(|d| d.have)
            .unwrap_or(false);
        parts.push(Part {
            peer_id: p.user_peer_id.clone(),
            eid: p.endpoint_id,
            have,
        });
    }
    parts.sort_by(|a, b| (!a.have, &a.peer_id).cmp(&(!b.have, &b.peer_id)));
    parts.dedup_by(|a, b| a.peer_id == b.peer_id);

    let num_old = parts.iter().filter(|p| p.have).count();
    let total = parts.len();
    let this_party = parts
        .iter()
        .position(|p| p.peer_id == peer_id)
        .ok_or_else(|| anyhow!("internal: self not in participant list"))?;
    info!(
        "participants ({total}): {:?}; {num_old} hold the old key; my index={this_party}",
        parts.iter().map(|p| &p.peer_id).collect::<Vec<_>>()
    );

    if num_old < old.old_t as usize {
        bail!(
            "need at least {} holders of the old key, only {num_old} present",
            old.old_t
        );
    }
    if total < new_n as usize {
        bail!("need at least {new_n} participants, only {total} present");
    }

    let mesh = net::connect_mesh(endpoint, lookup, my_eid, &others, timeout).await?;

    match (old.old_kind, new_t) {
        (Some(KeyKind::Tss), t) if t >= 2 => {
            tss_to_tss(peer_id, key_id, &parts, this_party, num_old, new_t, new_n, &old, existing, mesh, timeout)
                .await
        }
        (Some(KeyKind::Tss), 1) => {
            tss_to_singleton(peer_id, key_id, &parts, this_party, &old, existing, mesh, timeout).await
        }
        (Some(KeyKind::Singleton), t) if t >= 2 => {
            singleton_to_tss(peer_id, key_id, &parts, this_party, new_t, new_n, &old, existing, mesh, timeout)
                .await
        }
        (Some(KeyKind::Singleton), 1) => {
            // Same key, still singleton: just copy the secret to this peer's file.
            copy_singleton(peer_id, &old, existing)
        }
        (None, _) => bail!("no holder of key '{key_id}' is online to reshare from"),
        _ => bail!("unsupported reshare combination (t={new_t})"),
    }
}

/// Wait until the reshare can proceed and return discovered peers + old params.
async fn wait_for_reshare_quorum(
    discovery: &Discovery,
    me: &Descriptor,
    new_n: u8,
    timeout: Duration,
) -> Result<(Vec<PeerInfo>, Descriptor)> {
    use std::time::Instant;
    let start = Instant::now();
    let mut logged = 0usize;
    loop {
        let snap = discovery.snapshot();
        // Learn old params from self or any holder.
        let old = if me.have {
            Some(me.clone())
        } else {
            snap.iter()
                .filter_map(|p| Descriptor::decode(p.extra.as_deref().unwrap_or("")))
                .find(|d| d.have)
        };
        let num_old = (me.have as usize)
            + snap
                .iter()
                .filter(|p| {
                    Descriptor::decode(p.extra.as_deref().unwrap_or(""))
                        .map(|d| d.have)
                        .unwrap_or(false)
                })
                .count();
        let online = snap.len() + 1;
        if online != logged {
            info!("online peers: {online} ({num_old} hold the old key)");
            logged = online;
        }
        if let Some(old) = old {
            let need = (new_n as usize).max(old.old_t as usize);
            if online >= need && num_old >= old.old_t as usize {
                return Ok((snap, old));
            }
        }
        if start.elapsed() > timeout {
            bail!("timed out waiting for reshare quorum ({online} peers online)");
        }
        discovery.tick(Duration::from_secs(2)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn tss_to_tss(
    peer_id: &str,
    key_id: &str,
    parts: &[Part],
    this_party: usize,
    num_old: usize,
    new_t: u8,
    new_n: u8,
    old: &Descriptor,
    existing: Option<StoredKey>,
    mesh: net::Mesh,
    timeout: Duration,
) -> Result<()> {
    let total = parts.len();
    let old_parties: Vec<usize> = (0..num_old).collect();
    let new_parties: Vec<(usize, u8)> = (0..new_n as usize).map(|i| (i, 0u8)).collect();
    let vks: Vec<NoVerifyingKey> = (0..total).map(NoVerifyingKey::new).collect();
    let pubkey_pt = crypto::pubkey_hex_to_point(&old.pubkey)?;

    let peer_ids_joined = parts.iter().map(|p| p.peer_id.as_str()).collect::<Vec<_>>().join(",");
    let instance = ids::instance_id(
        "dkls23ctl/reshare/qc/v1",
        &[
            key_id.as_bytes(),
            &[old.old_t, old.old_n, new_t, new_n],
            peer_ids_joined.as_bytes(),
        ],
    );

    let my_keyshare: Option<Arc<Keyshare>> = if this_party < num_old {
        let stored = existing.as_ref().ok_or_else(|| anyhow!("missing local share"))?;
        Some(Arc::new(load_keyshare(stored)?))
    } else {
        None
    };

    let (relay, _handle) = mesh.into_relay();
    let setup = QcSetup::new(
        instance,
        this_party,
        &old_parties,
        &new_parties,
        new_t as usize,
        NoSigningKey,
        vks,
        pubkey_pt,
    )
    .with_keyshare_opt(my_keyshare)
    .with_ttl(MSG_TTL);

    info!("running quorum-change reshare...");
    let result = tokio::time::timeout(timeout, quorum_change::run(setup, fresh_seed(), relay))
        .await
        .map_err(|_| anyhow!("reshare timed out (a peer may have gone offline)"))?
        .map_err(|e| anyhow!("quorum-change failed: {e:?}"))?;

    match result {
        Some(new_keyshare) => {
            let committee: Vec<String> =
                parts.iter().take(new_n as usize).map(|p| p.peer_id.clone()).collect();
            store_tss(peer_id, key_id, new_t, new_n, &new_keyshare, committee)?;
            println!("{}", crypto::point_to_hex(&new_keyshare.public_key()));
        }
        None => {
            info!("this peer is not part of the new committee; no new share produced");
            println!("{}", old.pubkey);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn singleton_to_tss(
    peer_id: &str,
    key_id: &str,
    parts: &[Part],
    this_party: usize,
    new_t: u8,
    new_n: u8,
    old: &Descriptor,
    existing: Option<StoredKey>,
    mesh: net::Mesh,
    timeout: Duration,
) -> Result<()> {
    // The single holder (index 0) is the dealer: it splits the secret and sends
    // each new-committee member its pre-refresh share over an encrypted channel.
    // Then everyone runs key_refresh to finalize (re-randomized) shares.
    let committee: Vec<&Part> = parts.iter().take(new_n as usize).collect();
    let in_committee = this_party < new_n as usize;
    let (relay, mut handle) = mesh.into_relay();

    let chain_code: [u8; 32] = {
        let s = existing
            .as_ref()
            .map(|k| k.root_chain_code.clone())
            .or_else(|| Some(old.pubkey.clone())) // fallback; replaced below for dealer
            .unwrap_or_default();
        let mut cc = [0u8; 32];
        let bytes = hex::decode(&s).unwrap_or_default();
        if bytes.len() == 32 {
            cc.copy_from_slice(&bytes);
        }
        cc
    };

    // Distribute pre-refresh shares (dealer only).
    let my_refresh: Option<KeyshareForRefresh> = if this_party == 0 {
        let stored = existing.as_ref().ok_or_else(|| anyhow!("dealer missing secret"))?;
        let secret = parse_secret(stored)?;
        let sk = NonZeroScalar::from_repr(secret.into())
            .into_option()
            .ok_or_else(|| anyhow!("invalid secret scalar"))?;
        let ranks = vec![0u8; new_n as usize];
        let shares = ecdsa_secret_shares(
            new_t,
            ranks,
            &sk,
            chain_code,
            None,
            &mut rand::rngs::OsRng,
        );
        // Hand share i to committee member i (keep our own).
        let mut mine = None;
        for (i, member) in committee.iter().enumerate() {
            let bytes = shares[i].to_bytes();
            if member.peer_id == peer_id {
                mine = KeyshareForRefresh::from_bytes(&bytes);
            } else {
                handle
                    .send_control(member.eid, &bytes)
                    .with_context(|| format!("sending share to {}", member.peer_id))?;
            }
        }
        info!("dealer distributed {} pre-refresh shares", new_n);
        mine
    } else if in_committee {
        // Wait to receive our share from the dealer.
        let bytes = match tokio::time::timeout(timeout, handle.control_rx.recv()).await {
            Ok(Some((_from, payload))) => payload,
            _ => bail!("did not receive a pre-refresh share from the dealer"),
        };
        KeyshareForRefresh::from_bytes(&bytes)
    } else {
        None
    };

    if !in_committee {
        info!("this peer is not in the new committee; nothing to do");
        println!("{}", old.pubkey);
        return Ok(());
    }
    let my_refresh = my_refresh.ok_or_else(|| anyhow!("did not obtain a pre-refresh share"))?;

    // All committee members run key_refresh over the mesh.
    let vks: Vec<NoVerifyingKey> = (0..new_n as usize).map(NoVerifyingKey::new).collect();
    let ranks = vec![0u8; new_n as usize];
    let committee_ids: Vec<String> = committee.iter().map(|p| p.peer_id.clone()).collect();
    let instance = ids::instance_id(
        "dkls23ctl/reshare/import/v1",
        &[key_id.as_bytes(), &[new_t, new_n], committee_ids.join(",").as_bytes()],
    );
    let setup = KeygenSetup::new(instance, NoSigningKey, this_party, vks, &ranks, new_t as usize)
        .with_ttl(MSG_TTL);

    info!("running key-import refresh...");
    let new_keyshare = tokio::time::timeout(
        timeout,
        key_refresh::run(setup, fresh_seed(), relay, my_refresh),
    )
    .await
    .map_err(|_| anyhow!("import timed out"))?
    .map_err(|e| anyhow!("key-refresh failed: {e:?}"))?;

    store_tss(peer_id, key_id, new_t, new_n, &new_keyshare, committee_ids)?;
    println!("{}", crypto::point_to_hex(&new_keyshare.public_key()));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn tss_to_singleton(
    peer_id: &str,
    key_id: &str,
    parts: &[Part],
    this_party: usize,
    old: &Descriptor,
    existing: Option<StoredKey>,
    mesh: net::Mesh,
    timeout: Duration,
) -> Result<()> {
    // Receiver = participant 0 (a holder). Each holder sends (x_i, rank, s_i) to
    // the receiver, who reconstructs the secret via Lagrange interpolation.
    let receiver = &parts[0];
    let am_receiver = this_party == 0;
    let (_relay, mut handle) = mesh.into_relay();
    let stored = existing.as_ref().ok_or_else(|| anyhow!("missing local share"))?;
    let keyshare = load_keyshare(stored)?;
    let my_party_id = keyshare.party_id as usize;
    let x_i = keyshare.x_i_list()[my_party_id];
    let rank = keyshare.get_rank(my_party_id as u8);
    let s_i = keyshare.s_i();

    // Serialize our contribution: x_i (32) || rank (1) || s_i (32).
    let mut contribution = Vec::with_capacity(65);
    contribution.extend_from_slice(&x_i.to_bytes());
    contribution.push(rank);
    contribution.extend_from_slice(&s_i.to_bytes());

    if !am_receiver {
        handle
            .send_control(receiver.eid, &contribution)
            .context("sending share contribution to receiver")?;
        info!("sent share contribution to {}", receiver.peer_id);
        // Drain the relay briefly so the connection stays healthy, then finish.
        println!("{}", old.pubkey);
        return Ok(());
    }

    // Receiver: collect contributions until we have old_t of them (incl. ours).
    let need = old.old_t as usize;
    let mut x_list: Vec<(NonZeroScalar, usize)> = vec![(x_i, rank as usize)];
    let mut s_list: Vec<Scalar> = vec![s_i];
    let deadline = std::time::Instant::now() + timeout;
    while x_list.len() < need {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out collecting shares ({}/{need})", x_list.len());
        }
        let payload = match tokio::time::timeout(remaining, handle.control_rx.recv()).await {
            Ok(Some((_from, p))) => p,
            _ => bail!("connection closed while collecting shares"),
        };
        if payload.len() != 65 {
            continue;
        }
        let xb: [u8; 32] = payload[0..32].try_into().unwrap();
        let r = payload[32] as usize;
        let sb: [u8; 32] = payload[33..65].try_into().unwrap();
        let x = NonZeroScalar::from_repr(xb.into())
            .into_option()
            .ok_or_else(|| anyhow!("bad x_i in contribution"))?;
        let s = Scalar::from_repr(sb.into())
            .into_option()
            .ok_or_else(|| anyhow!("bad s_i in contribution"))?;
        x_list.push((x, r));
        s_list.push(s);
        info!("collected {}/{need} shares", x_list.len());
    }

    let pubkey_pt = crypto::pubkey_hex_to_point(&old.pubkey)?;
    let secret = combine_shares(&x_list, &s_list, &pubkey_pt)
        .ok_or_else(|| anyhow!("failed to reconstruct secret from shares"))?;
    let secret_bytes: [u8; 32] = secret.to_bytes().into();

    // Sanity: reconstructed secret must match the public key.
    let derived = crypto::singleton_public_key_hex(&secret_bytes)?;
    if derived != old.pubkey {
        bail!("reconstructed key does not match expected public key");
    }

    let stored_new = StoredKey {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        kind: KeyKind::Singleton,
        t: 1,
        n: 1,
        party_index: 0,
        participants: vec![peer_id.to_string()],
        public_key: old.pubkey.clone(),
        root_chain_code: stored.root_chain_code.clone(),
        keyshare_b64: None,
        secret_hex: Some(hex::encode(secret_bytes)),
    };
    stored_new.save()?;
    info!("reconstructed singleton key saved");
    println!("{}", old.pubkey);
    Ok(())
}

fn copy_singleton(peer_id: &str, old: &Descriptor, existing: Option<StoredKey>) -> Result<()> {
    let stored = existing.ok_or_else(|| anyhow!("only the current holder can re-store a singleton"))?;
    let mut new = stored.clone();
    new.peer_id = peer_id.to_string();
    new.save()?;
    println!("{}", old.pubkey);
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn store_tss(
    peer_id: &str,
    key_id: &str,
    t: u8,
    n: u8,
    keyshare: &Keyshare,
    participants: Vec<String>,
) -> Result<()> {
    let stored = StoredKey {
        key_id: key_id.to_string(),
        peer_id: peer_id.to_string(),
        kind: KeyKind::Tss,
        t,
        n,
        party_index: keyshare.party_id,
        participants,
        public_key: crypto::point_to_hex(&keyshare.public_key()),
        root_chain_code: hex::encode(keyshare.root_chain_code()),
        keyshare_b64: Some(b64().encode(keyshare.as_slice())),
        secret_hex: None,
    };
    let path = stored.save()?;
    info!("new key share saved to {}", path.display());
    Ok(())
}

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
    bytes.try_into().map_err(|_| anyhow!("secret is not 32 bytes"))
}
