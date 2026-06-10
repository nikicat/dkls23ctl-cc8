//! dkls23ctl — a fully peer-to-peer threshold-ECDSA (DKLS23) CLI.
//!
//! Each running instance is an equal peer. Instances that share a `--key-id`
//! discover one another over mDNS (no server, no leader), form a full mesh over
//! iroh/QUIC, and run the DKLS23 keygen / sign / reshare protocols. Results
//! (public key, signature) are printed to stdout; all logs go to stderr.

mod commands;
mod crypto;
mod ids;
mod net;
mod relay;
mod reshare;
mod session;
mod storage;

use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(
    name = "dkls23ctl",
    about = "Peer-to-peer threshold ECDSA (DKLS23) signing & key generation",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a (t-of-n) key share. Start N instances with the same --key-id.
    Keygen(KeygenArgs),
    /// Print the public key for a key-id (peer-agnostic).
    Pubkey(PubkeyArgs),
    /// Threshold-sign a message. Start at least T instances with the same --msg.
    Sign(SignArgs),
    /// Reshare an existing key to new (t-of-n) parameters (public key unchanged).
    Reshare(ReshareArgs),
    /// Verify a signature against a key-id's public key.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct KeygenArgs {
    /// Threshold: minimum signers required (t=1 generates a plain singleton key).
    #[arg(short = 't')]
    t: u8,
    /// Total number of shares. Defaults to the threshold value.
    #[arg(short = 'n')]
    n: Option<u8>,
    /// Unique identifier for THIS peer (must differ across peers).
    #[arg(long)]
    peer_id: String,
    /// Identifier of the key being generated (must match across all peers).
    #[arg(long)]
    key_id: String,
    /// Overall timeout in seconds for discovery + protocol.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

#[derive(Args)]
struct PubkeyArgs {
    #[arg(long)]
    key_id: String,
}

#[derive(Args)]
struct SignArgs {
    #[arg(long)]
    key_id: String,
    /// Identifier of this peer (must own a share for key_id).
    #[arg(long)]
    peer_id: String,
    /// The message to sign (hashed with SHA-256 before signing).
    #[arg(long)]
    msg: String,
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

#[derive(Args)]
struct ReshareArgs {
    #[arg(long)]
    peer_id: String,
    #[arg(long)]
    key_id: String,
    /// New threshold.
    #[arg(short = 't')]
    t: u8,
    /// New total share count. Defaults to the threshold value.
    #[arg(short = 'n')]
    n: Option<u8>,
    #[arg(long, default_value_t = 180)]
    timeout: u64,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long)]
    key_id: String,
    #[arg(long)]
    msg: String,
    /// Signature as compact r||s hex.
    #[arg(long)]
    signature: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // By default only show our own logs (peer counts, progress). iroh/swarm
    // internals (including iroh's noisy "Endpoint dropped" notice on exit) are
    // hidden unless the user opts in via RUST_LOG, e.g. RUST_LOG=iroh=debug.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("dkls23ctl=info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(a) => {
            let n = a.n.unwrap_or(a.t);
            commands::keygen(a.t, n, &a.peer_id, &a.key_id, Duration::from_secs(a.timeout)).await
        }
        Command::Pubkey(a) => commands::pubkey(&a.key_id),
        Command::Sign(a) => {
            commands::sign(&a.key_id, &a.peer_id, &a.msg, Duration::from_secs(a.timeout)).await
        }
        Command::Reshare(a) => {
            let n = a.n.unwrap_or(a.t);
            reshare::run(&a.peer_id, &a.key_id, a.t, n, Duration::from_secs(a.timeout)).await
        }
        Command::Verify(a) => commands::verify(&a.key_id, &a.msg, &a.signature),
    }
}
