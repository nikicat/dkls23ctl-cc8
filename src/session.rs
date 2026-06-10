//! Shared orchestration: bind → discover → wait for quorum → connect mesh →
//! build a [`IrohRelay`] ready to drive a DKLS23 protocol.

use std::time::Duration;

use anyhow::Result;
use tracing::info;

use crate::{
    net::{self, Discovery, MeshHandle, PeerInfo},
    relay::IrohRelay,
};
use iroh::EndpointId;

/// Everything a command needs after the network is up.
pub struct Session {
    pub relay: IrohRelay,
    /// Control messaging + keep-alive (endpoint/connections/tasks). Held for the
    /// session's lifetime so connections stay open during the protocol.
    #[allow(dead_code)]
    pub handle: MeshHandle,
    /// Discovered peers (excludes self).
    pub peers: Vec<PeerInfo>,
    /// Our own endpoint id.
    pub my_eid: EndpointId,
    /// Keeps mDNS advertising/resolving alive for the session's lifetime.
    pub _discovery: Discovery,
}

/// Bind, advertise on `service`, wait for `total_needed` peers (self included),
/// then connect a full mesh and return a ready relay.
///
/// `settle` is a short grace period after quorum is reached so every peer
/// converges on the same participant set before connecting.
pub async fn establish(
    service: &str,
    my_user_peer_id: &str,
    extra: Option<String>,
    total_needed: usize,
    settle: Duration,
    timeout: Duration,
) -> Result<Session> {
    let (endpoint, lookup) = net::bind_endpoint().await?;
    let my_eid = endpoint.id();
    let port = net::endpoint_port(&endpoint)?;
    let ips = net::local_ipv4s();
    info!(
        "this peer: endpoint={} udp_port={} addrs={:?}",
        my_eid.fmt_short(),
        port,
        ips
    );

    let discovery = Discovery::start(service, my_eid, my_user_peer_id, extra, port, ips)?;
    discovery.wait_for_quorum(total_needed, timeout).await?;

    // Let the participant set settle so everyone agrees who is in.
    tokio::time::sleep(settle).await;
    let peers = discovery.snapshot();
    info!("quorum reached: {} peer(s) online", peers.len() + 1);

    let mesh = net::connect_mesh(endpoint, lookup, my_eid, &peers, timeout).await?;
    let (relay, handle) = mesh.into_relay();

    Ok(Session {
        relay,
        handle,
        peers,
        my_eid,
        _discovery: discovery,
    })
}
