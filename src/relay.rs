//! A distributed implementation of `sl_mpc_mate::coord::Relay` over iroh.
//!
//! ## How the reference (in-memory) relay works
//!
//! DKLS23 drives its protocols through a `Relay`, which is a `Stream + Sink` of
//! opaque `Vec<u8>` messages. Each message starts with a [`MsgHdr`] carrying a
//! [`MsgId`] and TTL. There are two kinds of traffic:
//!
//! * **Pub** — a real protocol message (`len > MESSAGE_HEADER_SIZE`).
//! * **Ask** — a header-only request (`len == MESSAGE_HEADER_SIZE`) saying
//!   "deliver me the message with this id when it appears".
//!
//! The bundled `SimpleMessageRelay` is a shared in-memory hub keyed by `MsgId`:
//! a party publishes a Pub and other parties Ask for it. The protocol messages
//! are already end-to-end signed/encrypted, so a point-to-point message is only
//! ever Asked for by its intended recipient (its id encodes the receiver).
//!
//! ## The distributed version
//!
//! We give every peer its own local copy of that store and connect them with a
//! broadcast bus:
//!
//! * **Ask** is handled purely locally (register a waiter / return a ready msg).
//! * **Pub** is stored locally *and* broadcast to every connected peer.
//! * Pubs **received** from peers are fed into the local store, waking waiters.
//!
//! Because every Pub reaches every peer's store, an Ask is always eventually
//! satisfied exactly as it would be against the central hub. Non-recipients of a
//! point-to-point message simply never Ask for it (and couldn't decrypt it).
//!
//! The store/expiry logic is a faithful port of the reference `SimpleMessageRelay`.

use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BinaryHeap, HashMap},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_util::{Sink, Stream};
use tokio::sync::mpsc;

use sl_mpc_mate::{
    coord::{MessageSendError, Relay},
    message::{Kind, MsgHdr, MsgId, MESSAGE_HEADER_SIZE},
};

/// Heap entry for TTL-based cleanup. Ordering is reversed so the `BinaryHeap`
/// behaves as a min-heap on the expiry instant.
#[derive(Debug)]
struct Expire(Instant, MsgId, Kind);

impl PartialEq for Expire {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}
impl Eq for Expire {}
impl PartialOrd for Expire {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Expire {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

enum MsgEntry {
    Waiters((Instant, Vec<mpsc::Sender<Vec<u8>>>)),
    Ready(Vec<u8>),
}

/// Per-peer message store, keyed by `MsgId`. Faithful port of the reference
/// `SimpleMessageRelay::Inner`.
#[derive(Default)]
struct Inner {
    expire: BinaryHeap<Expire>,
    messages: HashMap<MsgId, MsgEntry>,
}

impl Inner {
    fn new() -> Self {
        Self::default()
    }

    fn cleanup_later(&mut self, id: &MsgId, expire: Instant, kind: Kind) {
        self.expire.push(Expire(expire, *id, kind));
    }

    fn cleanup(&mut self, now: Instant) {
        while let Some(Expire(when, id, kind)) = self.expire.peek() {
            if *when > now {
                break;
            }
            if let Entry::Occupied(ocp) = self.messages.entry(*id) {
                if match ocp.get() {
                    MsgEntry::Ready(_) => kind == &Kind::Pub,
                    MsgEntry::Waiters((expire, _)) => kind == &Kind::Ask && *expire <= now,
                } {
                    ocp.remove();
                }
            }
            self.expire.pop();
        }
    }

    /// Publish a real message and wake any waiters for its id.
    fn send(&mut self, msg: Vec<u8>) {
        if msg.len() <= MESSAGE_HEADER_SIZE {
            return; // not a Pub; ignore defensively
        }
        let hdr: &MsgHdr = match msg.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => return,
        };
        let now = Instant::now();
        let expire = now + hdr.ttl();
        let id = *hdr.id();

        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => match ocp.get_mut() {
                MsgEntry::Waiters((_, b)) => {
                    for tx in b.drain(..) {
                        let msg = msg.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(msg).await;
                        });
                    }
                    ocp.insert(MsgEntry::Ready(msg));
                    self.cleanup_later(&id, expire, Kind::Pub);
                }
                MsgEntry::Ready(_) => { /* ignore duplicates */ }
            },
            Entry::Vacant(vac) => {
                vac.insert(MsgEntry::Ready(msg));
                self.cleanup_later(&id, expire, Kind::Pub);
            }
        }
    }

    /// Register interest in a message id; return it immediately if already ready.
    fn recv(&mut self, id: MsgId, ttl: Duration, tx: &mpsc::Sender<Vec<u8>>) -> Option<Vec<u8>> {
        let now = Instant::now();
        let expire = now + ttl;
        self.cleanup(now);

        match self.messages.entry(id) {
            Entry::Occupied(mut ocp) => match ocp.get_mut() {
                MsgEntry::Ready(msg) => return Some(msg.clone()),
                MsgEntry::Waiters((prev, b)) => {
                    *prev = expire.max(*prev);
                    b.push(tx.clone());
                    self.cleanup_later(&id, expire, Kind::Ask);
                }
            },
            Entry::Vacant(vac) => {
                vac.insert(MsgEntry::Waiters((expire, vec![tx.clone()])));
                self.cleanup_later(&id, expire, Kind::Ask);
            }
        }
        None
    }
}

/// Feeds messages received from peers into a relay's local store.
#[derive(Clone)]
pub struct Feeder {
    inner: Arc<Mutex<Inner>>,
}

impl Feeder {
    /// Inject a Pub message received from a remote peer.
    pub fn feed(&self, msg: Vec<u8>) {
        self.inner.lock().unwrap().send(msg);
    }
}

/// `Relay` implementation backed by a local store + an outbound broadcast bus.
pub struct IrohRelay {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    queue: Vec<Vec<u8>>,
    inner: Arc<Mutex<Inner>>,
    /// Every Pub is pushed here; the network layer fans it out to all peers.
    outbound: mpsc::UnboundedSender<Vec<u8>>,
}

impl IrohRelay {
    /// Create a relay plus a [`Feeder`]. Drive the feeder from the inbound
    /// network stream: `while let Some(m) = inbound.recv().await { feeder.feed(m) }`.
    pub fn new(outbound: mpsc::UnboundedSender<Vec<u8>>) -> (Self, Feeder) {
        let (tx, rx) = mpsc::channel(1024);
        let inner = Arc::new(Mutex::new(Inner::new()));
        let feeder = Feeder {
            inner: inner.clone(),
        };
        (
            Self {
                rx,
                tx,
                queue: vec![],
                inner,
                outbound,
            },
            feeder,
        )
    }
}

impl Stream for IrohRelay {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(msg) = self.queue.pop() {
            Poll::Ready(Some(msg))
        } else {
            self.rx.poll_recv(cx)
        }
    }
}

impl Sink<Vec<u8>> for IrohRelay {
    type Error = MessageSendError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let hdr: &MsgHdr = item.as_slice().try_into().map_err(|_| MessageSendError)?;

        if item.len() == MESSAGE_HEADER_SIZE {
            // Ask: satisfy locally now or register a waiter.
            let id = *hdr.id();
            let ttl = hdr.ttl();
            if let Some(msg) = this.inner.lock().unwrap().recv(id, ttl, &this.tx) {
                this.queue.push(msg);
            }
        } else {
            // Pub: keep a local copy (faithful to the hub) and broadcast to peers.
            this.inner.lock().unwrap().send(item.clone());
            let _ = this.outbound.send(item);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Relay for IrohRelay {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use sl_dkls23::{
        keygen, sign,
        setup::{
            keygen::SetupMessage as KeygenSetup, sign::SetupMessage as SignSetup, NoSigningKey,
            NoVerifyingKey,
        },
        InstanceId,
    };
    use sl_dkls23::k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    /// Build `n` relays wired together by an in-process broadcast bus: every Pub
    /// one relay emits is fed into the local store of all the others. This mirrors
    /// exactly what the iroh mesh does, but with no network, so it isolates and
    /// validates the relay's Ask/Pub matching logic.
    fn wire_bus(n: usize) -> Vec<IrohRelay> {
        let mut relays = Vec::new();
        let mut feeders = Vec::new();
        let mut outs = Vec::new();
        for _ in 0..n {
            let (otx, orx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (relay, feeder) = IrohRelay::new(otx);
            relays.push(relay);
            feeders.push(feeder);
            outs.push(orx);
        }
        for (i, mut orx) in outs.into_iter().enumerate() {
            let others: Vec<Feeder> = feeders
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, f)| f.clone())
                .collect();
            tokio::spawn(async move {
                while let Some(msg) = orx.recv().await {
                    for f in &others {
                        f.feed(msg.clone());
                    }
                }
            });
        }
        relays
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relay_drives_keygen_and_sign() {
        let t = 2usize;
        let n = 3usize;

        // --- DKG over the relay bus ---
        let relays = wire_bus(n);
        let instance = InstanceId::new([7u8; 32]);
        let vks: Vec<NoVerifyingKey> = (0..n).map(NoVerifyingKey::new).collect();
        let ranks = vec![0u8; n];

        let mut jset = tokio::task::JoinSet::new();
        for (i, relay) in relays.into_iter().enumerate() {
            let setup = KeygenSetup::new(instance, NoSigningKey, i, vks.clone(), &ranks, t)
                .with_ttl(Duration::from_secs(30));
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            jset.spawn(keygen::run(setup, seed, relay));
        }
        let mut shares: Vec<Arc<keygen::Keyshare>> = Vec::new();
        while let Some(r) = jset.join_next().await {
            shares.push(Arc::new(r.unwrap().expect("keygen ok")));
        }
        assert_eq!(shares.len(), n);
        let pk = shares[0].public_key();
        for s in &shares {
            assert_eq!(s.public_key(), pk, "all parties must agree on the public key");
        }

        // --- DSG with t signers over a fresh relay bus ---
        shares.sort_by_key(|s| s.party_id);
        let signers: Vec<Arc<keygen::Keyshare>> = shares[..t].to_vec();
        let relays = wire_bus(t);
        let inst2 = InstanceId::new([9u8; 32]);
        let vks2: Vec<NoVerifyingKey> = signers
            .iter()
            .map(|s| NoVerifyingKey::new(s.party_id as usize))
            .collect();
        let hash = [42u8; 32];

        let mut jset = tokio::task::JoinSet::new();
        for (idx, (relay, share)) in relays.into_iter().zip(signers.iter()).enumerate() {
            let setup = SignSetup::new(inst2, NoSigningKey, idx, vks2.clone(), share.clone())
                .with_hash(hash)
                .with_ttl(Duration::from_secs(30));
            let mut seed = [0u8; 32];
            seed[0] = 100 + idx as u8;
            jset.spawn(sign::run(setup, seed, relay));
        }
        let mut sigs: Vec<Signature> = Vec::new();
        while let Some(r) = jset.join_next().await {
            let (sig, _recid) = r.unwrap().expect("sign ok");
            sigs.push(sig);
        }
        assert_eq!(sigs.len(), t);
        // Every signer produces the same signature, and it verifies under pk.
        let vk = VerifyingKey::from_affine(pk.to_affine()).unwrap();
        for sig in &sigs {
            assert!(vk.verify_prehash(&hash, sig).is_ok(), "signature must verify");
        }
    }
}
