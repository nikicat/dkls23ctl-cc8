//! Peer discovery (mDNS via swarm-discovery) and a full-mesh iroh transport that
//! feeds the [`crate::relay::IrohRelay`].
//!
//! Peers that share a key id (and operation) advertise the same mDNS service
//! name, so they find each other with no server and no prior knowledge of each
//! other's addresses. Once a quorum is present we connect every pair exactly
//! once (the peer with the smaller endpoint id dials) and run a length-prefixed
//! frame protocol on a single bidirectional QUIC stream per peer.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use iroh::{
    address_lookup::memory::MemoryLookup,
    endpoint::{presets, Connection},
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use swarm_discovery::Discoverer;
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};
use tracing::{debug, info, warn};

/// Application-layer protocol id for our QUIC connections.
pub const ALPN: &[u8] = b"dkls23ctl/1";

/// Priming frame the dialer sends right after opening its stream. QUIC creates a
/// bidirectional stream lazily, so the acceptor's `accept_bi()` does not resolve
/// until the first bytes arrive; this unblocks it before any protocol traffic.
/// It is shorter than a DKLS23 message header, so the relay store ignores it.
const PRIME: &[u8] = b"DK23HELO";

/// A discovered remote peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub endpoint_id: EndpointId,
    /// User-supplied `--peer-id` string (carried in mDNS TXT).
    pub user_peer_id: String,
    /// Optional extra attribute (e.g. a keyshare party id for signing).
    pub extra: Option<String>,
    pub addrs: Vec<SocketAddr>,
}

/// Best-effort list of this host's usable IPv4 addresses (LAN address first,
/// loopback last) so same-host and cross-host peers can both connect.
pub fn local_ipv4s() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Doesn't send anything; just learns the kernel's chosen source address.
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if addr.ip().is_ipv4() && !addr.ip().is_loopback() {
                    ips.push(addr.ip());
                }
            }
        }
    }
    ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips
}

/// Bind an iroh endpoint for LAN/localhost use: a fresh identity, our ALPN,
/// relays disabled, and a [`MemoryLookup`] we populate with peer addresses
/// discovered over mDNS (so iroh can resolve and connect by endpoint id).
pub async fn bind_endpoint() -> Result<(Endpoint, MemoryLookup)> {
    let secret_key = SecretKey::generate();
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .address_lookup(lookup.clone())
        .bind()
        .await
        .map_err(|e| anyhow!("failed to bind iroh endpoint: {e}"))?;
    Ok((endpoint, lookup))
}

/// Running mDNS discovery for one operation.
pub struct Discovery {
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    notify: Arc<Notify>,
    _guard: swarm_discovery::DropGuard,
}

impl Discovery {
    /// Start advertising ourselves and discovering peers on `service`.
    pub fn start(
        service: &str,
        my_eid: EndpointId,
        my_user_peer_id: &str,
        extra: Option<String>,
        port: u16,
        ips: Vec<IpAddr>,
    ) -> Result<Discovery> {
        let peers: Arc<Mutex<HashMap<String, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
        let notify = Arc::new(Notify::new());
        // The full endpoint id (64 hex chars) is too long for a DNS label, so the
        // mDNS peer id is a short prefix and the full id travels in a TXT record.
        let full_eid = hex::encode(my_eid.as_bytes());
        let node_label = full_eid[..32].to_string();

        let mut txt: Vec<(String, Option<String>)> = vec![
            ("eid".to_string(), Some(full_eid)),
            ("pid".to_string(), Some(my_user_peer_id.to_string())),
        ];
        if let Some(e) = &extra {
            txt.push(("px".to_string(), Some(e.clone())));
        }

        let peers_cb = peers.clone();
        let notify_cb = notify.clone();
        let me_cb = node_label.clone();

        let guard = Discoverer::new(service.to_string(), node_label)
            .with_addrs(port, ips)
            .with_txt_attributes(txt)
            .map_err(|e| anyhow!("invalid mDNS TXT: {e:?}"))?
            .with_callback(move |peer_id, peer| {
                if peer_id == me_cb {
                    return;
                }
                let eid = match peer
                    .txt_attribute("eid")
                    .flatten()
                    .and_then(|s| EndpointId::from_str(s).ok())
                {
                    Some(e) => e,
                    None => return,
                };
                let addrs: Vec<SocketAddr> = peer
                    .addrs()
                    .iter()
                    .map(|(ip, port)| SocketAddr::new(*ip, *port))
                    .collect();
                if addrs.is_empty() {
                    return;
                }
                let user_peer_id = peer
                    .txt_attribute("pid")
                    .flatten()
                    .unwrap_or(peer_id)
                    .to_string();
                let extra = peer.txt_attribute("px").flatten().map(|s| s.to_string());
                let info = PeerInfo {
                    endpoint_id: eid,
                    user_peer_id,
                    extra,
                    addrs,
                };
                peers_cb.lock().unwrap().insert(peer_id.to_string(), info);
                notify_cb.notify_waiters();
            })
            .spawn(&tokio::runtime::Handle::current())
            .map_err(|e| anyhow!("failed to start mDNS discovery: {e:?}"))?;

        Ok(Discovery {
            peers,
            notify,
            _guard: guard,
        })
    }

    /// Current snapshot of discovered peers (excludes self).
    pub fn snapshot(&self) -> Vec<PeerInfo> {
        self.peers.lock().unwrap().values().cloned().collect()
    }

    /// Online count *including* ourselves.
    pub fn online_count(&self) -> usize {
        self.peers.lock().unwrap().len() + 1
    }

    /// Wait until discovery changes or `max` elapses (whichever first).
    pub async fn tick(&self, max: Duration) {
        tokio::select! {
            _ = self.notify.notified() => {}
            _ = tokio::time::sleep(max) => {}
        }
    }

    /// Block until at least `total_needed` peers (self included) are online, then
    /// return the discovered peers (excluding self). Logs the live count.
    pub async fn wait_for_quorum(
        &self,
        total_needed: usize,
        timeout: Duration,
    ) -> Result<Vec<PeerInfo>> {
        let start = Instant::now();
        let mut last_logged = 0usize;
        loop {
            let n = self.online_count();
            if n != last_logged {
                info!("online peers: {n}/{total_needed}");
                last_logged = n;
            }
            if n >= total_needed {
                return Ok(self.snapshot());
            }
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "timed out waiting for quorum ({n}/{total_needed} peers online)"
                ));
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
    }
}

/// Frame type tags (first byte of every frame).
const FRAME_RELAY: u8 = 0; // DKLS23 relay traffic (broadcast)
const FRAME_CONTROL: u8 = 1; // application control message (point-to-point)

/// Keeps the endpoint, connections, and IO tasks alive for the mesh's lifetime.
pub struct MeshKeep {
    _endpoint: Endpoint,
    _lookup: MemoryLookup,
    _conns: Vec<Connection>,
    _tasks: Vec<JoinHandle<()>>,
}

/// A connected full mesh.
///
/// * Relay traffic: push into `outbound_tx` (broadcast to all peers); receive
///   from `inbound_rx`.
/// * Control traffic: [`Mesh::send_control`] to one peer; receive from
///   `control_rx` as `(sender_endpoint_id, payload)`. Used for the secure
///   point-to-point share distribution in singleton import/export.
pub struct Mesh {
    pub outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub control_rx: mpsc::UnboundedReceiver<(EndpointId, Vec<u8>)>,
    control_txs: HashMap<EndpointId, mpsc::UnboundedSender<Vec<u8>>>,
    pub keep: MeshKeep,
}

/// What remains of a [`Mesh`] after the relay is split out: control messaging
/// plus the keep-alive handle.
pub struct MeshHandle {
    pub control_rx: mpsc::UnboundedReceiver<(EndpointId, Vec<u8>)>,
    control_txs: HashMap<EndpointId, mpsc::UnboundedSender<Vec<u8>>>,
    /// Held only to keep the endpoint/connections/tasks alive (RAII).
    #[allow(dead_code)]
    pub keep: MeshKeep,
}

impl MeshHandle {
    /// Send a control message to a single peer over its (encrypted) connection.
    pub fn send_control(&self, to: EndpointId, payload: &[u8]) -> Result<()> {
        let tx = self
            .control_txs
            .get(&to)
            .ok_or_else(|| anyhow!("no connection to {}", to.fmt_short()))?;
        let mut frame = Vec::with_capacity(payload.len() + 1);
        frame.push(FRAME_CONTROL);
        frame.extend_from_slice(payload);
        tx.send(frame).map_err(|_| anyhow!("peer disconnected"))
    }
}

impl Mesh {
    /// Split the mesh into a DKLS23 [`IrohRelay`] and a [`MeshHandle`] for
    /// control messaging. Spawns the task that feeds received relay traffic into
    /// the relay's local store.
    pub fn into_relay(self) -> (crate::relay::IrohRelay, MeshHandle) {
        let (relay, feeder) = crate::relay::IrohRelay::new(self.outbound_tx);
        let mut inbound = self.inbound_rx;
        tokio::spawn(async move {
            while let Some(msg) = inbound.recv().await {
                feeder.feed(msg);
            }
        });
        (
            relay,
            MeshHandle {
                control_rx: self.control_rx,
                control_txs: self.control_txs,
                keep: self.keep,
            },
        )
    }
}

async fn connect_with_retry(
    endpoint: &Endpoint,
    id: EndpointId,
    deadline: Instant,
) -> Result<Connection> {
    let mut attempt = 0u32;
    loop {
        match endpoint.connect(id, ALPN).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(anyhow!("connect to {} failed: {e}", id.fmt_short()));
                }
                attempt += 1;
                debug!("connect attempt {attempt} to {} failed: {e}", id.fmt_short());
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

/// Establish connections to every peer (exactly one per pair) and wire up the
/// broadcast/receive plumbing.
pub async fn connect_mesh(
    endpoint: Endpoint,
    lookup: MemoryLookup,
    me: EndpointId,
    others: &[PeerInfo],
    timeout: Duration,
) -> Result<Mesh> {
    let deadline = Instant::now() + timeout;

    // Teach iroh how to reach every peer (addresses learned over mDNS).
    for p in others {
        let addr = EndpointAddr::from_parts(
            p.endpoint_id,
            p.addrs.iter().cloned().map(TransportAddr::Ip),
        );
        lookup.add_endpoint_info(addr);
    }

    // Deterministic direction: the smaller endpoint id dials, the larger accepts.
    let mut dial: Vec<PeerInfo> = Vec::new();
    let mut accept_ids: HashSet<EndpointId> = HashSet::new();
    for p in others {
        if me.as_bytes() < p.endpoint_id.as_bytes() {
            dial.push(p.clone());
        } else {
            accept_ids.insert(p.endpoint_id);
        }
    }
    let n_accept = accept_ids.len();
    info!(
        "connecting mesh: dialing {} peer(s), accepting {} peer(s)",
        dial.len(),
        n_accept
    );

    // Accept side.
    let ep_accept = endpoint.clone();
    let accept_fut = async move {
        let mut conns = Vec::new();
        while conns.len() < n_accept {
            let incoming = match ep_accept.accept().await {
                Some(i) => i,
                None => return Err(anyhow!("endpoint closed while accepting")),
            };
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("incoming connection failed: {e}");
                    continue;
                }
            };
            let rid = conn.remote_id();
            let (send, recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("accept_bi from {} failed: {e}", rid.fmt_short());
                    continue;
                }
            };
            debug!("accepted connection from {}", rid.fmt_short());
            conns.push((rid, conn, send, recv));
        }
        Ok::<_, anyhow::Error>(conns)
    };

    // Dial side.
    let ep_dial = endpoint.clone();
    let dial_peers = dial.clone();
    let dial_fut = async move {
        let mut conns = Vec::new();
        for p in dial_peers {
            let conn = connect_with_retry(&ep_dial, p.endpoint_id, deadline).await?;
            let (mut send, recv) = conn
                .open_bi()
                .await
                .map_err(|e| anyhow!("open_bi to {} failed: {e}", p.endpoint_id.fmt_short()))?;
            // Prime the stream so the peer's accept_bi() resolves promptly.
            {
                use tokio::io::AsyncWriteExt;
                send.write_u32(PRIME.len() as u32)
                    .await
                    .map_err(|e| anyhow!("priming write failed: {e}"))?;
                send.write_all(PRIME)
                    .await
                    .map_err(|e| anyhow!("priming write failed: {e}"))?;
                send.flush().await.ok();
            }
            debug!("dialed connection to {}", p.endpoint_id.fmt_short());
            conns.push((p.endpoint_id, conn, send, recv));
        }
        Ok::<_, anyhow::Error>(conns)
    };

    let (accepted, dialed) =
        match tokio::time::timeout(timeout, async { tokio::try_join!(accept_fut, dial_fut) }).await {
            Ok(r) => r?,
            Err(_) => return Err(anyhow!("mesh connection setup timed out")),
        };

    // Wire up IO tasks for every connection.
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (control_in_tx, control_rx) = mpsc::unbounded_channel::<(EndpointId, Vec<u8>)>();
    let mut peer_txs: Vec<mpsc::UnboundedSender<Vec<u8>>> = Vec::new();
    let mut control_txs: HashMap<EndpointId, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let mut conns_keep: Vec<Connection> = Vec::new();
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    for (eid, conn, mut send, mut recv) in accepted.into_iter().chain(dialed.into_iter()) {
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        peer_txs.push(out_tx.clone());
        control_txs.insert(eid, out_tx);
        conns_keep.push(conn);

        // Writer: drain this peer's outbound queue, length-prefix each frame.
        tasks.push(tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(frame) = out_rx.recv().await {
                if send.write_u32(frame.len() as u32).await.is_err()
                    || send.write_all(&frame).await.is_err()
                    || send.flush().await.is_err()
                {
                    break;
                }
            }
        }));

        // Reader: parse length-prefixed frames and route by type tag.
        let in_tx = inbound_tx.clone();
        let ctrl_tx = control_in_tx.clone();
        tasks.push(tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            loop {
                let len = match recv.read_u32().await {
                    Ok(l) => l as usize,
                    Err(_) => break,
                };
                if len == 0 || len > 64 * 1024 * 1024 {
                    break;
                }
                let mut buf = vec![0u8; len];
                if recv.read_exact(&mut buf).await.is_err() {
                    break;
                }
                match buf[0] {
                    FRAME_RELAY => {
                        if in_tx.send(buf[1..].to_vec()).is_err() {
                            break;
                        }
                    }
                    FRAME_CONTROL => {
                        if ctrl_tx.send((eid, buf[1..].to_vec())).is_err() {
                            break;
                        }
                    }
                    // Priming frame (and anything else) is ignored.
                    _ => {}
                }
            }
        }));
    }
    drop(inbound_tx);
    drop(control_in_tx);

    // Fan-out: relay Pubs -> every peer's writer (tagged FRAME_RELAY).
    let (outbound_tx, mut fan_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tasks.push(tokio::spawn(async move {
        while let Some(msg) = fan_rx.recv().await {
            let mut frame = Vec::with_capacity(msg.len() + 1);
            frame.push(FRAME_RELAY);
            frame.extend_from_slice(&msg);
            for tx in &peer_txs {
                let _ = tx.send(frame.clone());
            }
        }
    }));

    Ok(Mesh {
        outbound_tx,
        inbound_rx,
        control_rx,
        control_txs,
        keep: MeshKeep {
            _endpoint: endpoint,
            _lookup: lookup,
            _conns: conns_keep,
            _tasks: tasks,
        },
    })
}

/// Pick a UDP port this endpoint is bound to (preferring IPv4).
pub fn endpoint_port(endpoint: &Endpoint) -> Result<u16> {
    let socks = endpoint.bound_sockets();
    socks
        .iter()
        .find(|s| s.is_ipv4())
        .or_else(|| socks.first())
        .map(|s| s.port())
        .ok_or_else(|| anyhow!("endpoint has no bound sockets"))
}
