# dkls23ctl

A fully peer-to-peer CLI for **threshold ECDSA** (secp256k1) key generation and
signing, built on:

* [silence-laboratories/dkls23](https://github.com/silence-laboratories/dkls23)
  (`sl-dkls23`) — the DKLS23 threshold-ECDSA protocol engine.
* [n0-computer/iroh](https://github.com/n0-computer/iroh) — authenticated,
  encrypted QUIC transport.
* [`swarm-discovery`](https://crates.io/crates/swarm-discovery) — the iroh
  ecosystem's mDNS implementation, used for local peer discovery.

Every running instance is an **equal peer**: there is no server and no leader.
Instances that share a `--key-id` find each other over mDNS on localhost/LAN,
form a full mesh over iroh, and run the protocol together.

## How it works

* **Discovery.** Each operation derives an mDNS service name from a hardcoded
  tool id, the operation, and a fingerprint of the binding parameters (key id,
  and for signing the message hash). Only peers in the same session discover each
  other. Each peer publishes its iroh endpoint id and `--peer-id` in mDNS TXT
  records, so peers can both enumerate the group and learn how to connect. The
  live online-peer count is logged by every instance.
* **Quorum.** Each operation waits until enough peers are present (N for keygen,
  T for signing, `max(N, old_T)` for reshare), then proceeds. If a peer drops
  mid-protocol, the operation fails on timeout.
* **Transport / relay.** DKLS23 drives its rounds through a `Relay` (a
  `Stream + Sink` of opaque messages addressed by id). We implement that relay
  over iroh as a broadcast bus: every protocol message is broadcast to all peers
  and matched locally by id. DKLS23 messages are already end-to-end
  signed/encrypted, so point-to-point messages are only ever consumed by their
  intended recipient. See [`src/relay.rs`](src/relay.rs).
* **Deterministic setup.** With no leader, every peer independently derives the
  same protocol `InstanceId` and the same party ordering from values all peers
  agree on (key id, parameters, sorted committee, message). See
  [`src/ids.rs`](src/ids.rs).

## Build

```sh
cargo build           # debug build (used throughout; fast iteration)
```

## Subcommands

```sh
# Key generation (t-of-n). Start N instances in parallel with the same --key-id
# and distinct --peer-id values. t=1 generates a plain (singleton) ECDSA key
# locally with no networking. -n defaults to -t.
dkls23ctl keygen -t 2 -n 3 --peer-id alice --key-id mykey

# Show the public key for a key id (peer-agnostic; same for all peers).
dkls23ctl pubkey --key-id mykey

# Threshold sign. Start at least T instances with the same --msg and --key-id.
dkls23ctl sign --key-id mykey --peer-id alice --msg "hello"

# Reshare to new (t-of-n). Public key is preserved. Start max(N, old_T) peers.
# Works TSS<->TSS (quorum change) and singleton<->TSS (import/export).
dkls23ctl reshare --peer-id alice --key-id mykey -t 3 -n 5

# Verify a signature (compact r||s hex) against a key id's public key.
dkls23ctl verify --key-id mykey --msg "hello" --signature <hex>
```

Key shares are stored at `./.secrets/<key_id>/<peer_id>.json`, including the
generation parameters and the public key. Logs go to **stderr**; the only thing
printed to **stdout** is the result (public key or signature), so the commands
compose in scripts. Set `RUST_LOG=dkls23ctl=info` (or `iroh=debug`) for detail.

## Worked example (three terminals)

```sh
# terminal 1            # terminal 2             # terminal 3
dkls23ctl keygen -t2 -n3 --peer-id a --key-id k   (…--peer-id b…)   (…--peer-id c…)
# each prints the same public key

# sign with any 2 of the 3:
dkls23ctl sign --key-id k --peer-id a --msg hi    dkls23ctl sign --key-id k --peer-id c --msg hi
# both print the same signature

dkls23ctl verify --key-id k --msg hi --signature <sig>
```

## Helper scripts

For driving multiple peers on one host (QA / demos):

```sh
scripts/keygen.sh 2 3 mykey alice bob carol      # parallel keygen committee
scripts/sign.sh mykey "hello" alice carol        # parallel threshold sign + verify
scripts/reshare.sh mykey 2 4 alice bob carol dave # parallel reshare
scripts/qa.sh                                     # full automated scenario suite
```

## Tests

```sh
cargo test
```

* `crypto::tests` — singleton sign/verify roundtrip, public-key derivation.
* `relay::tests::relay_drives_keygen_and_sign` — wires N `IrohRelay`s together by
  an in-process broadcast bus and runs a real DKG + DSG, asserting all parties
  agree on the public key and the threshold signature verifies. This validates
  the relay logic independently of the network.

`scripts/qa.sh` is the end-to-end check using the built binary across every
scenario (singleton, 2-of-3, 3-of-5, all reshare directions, and a
below-threshold negative test).

## Notes & limitations

* Designed for localhost / LAN. iroh relays are disabled; peers connect directly
  using addresses learned over mDNS.
* `InstanceId`s are derived deterministically (no negotiation round). Signing the
  same message for the same key id twice reuses the session id; each run still
  uses fresh per-party randomness for nonces.
* Reshare conventions: participants are ordered "old-holders first, then by peer
  id"; the new committee is the first N. For TSS→singleton export the
  reconstructing peer is the lexicographically-first holder.
* Pinned dependency versions: `sl-dkls23 1.0.0-beta` requires
  `sl-mpc-mate = "=1.0.0-beta"` and `sl-oblivious = "=1.0.0-beta"` (newer
  releases changed APIs the beta can't build against).
