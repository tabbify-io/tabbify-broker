//! Broker binary: load creds from the 0600 non-env files, then serve on
//! `BROKER_SOCKET`. Runs as the privileged `broker` uid (set by `/init`).
//!
//! `tabbify-broker --scrub` is a one-shot CLIENT mode: it connects to the
//! running broker's socket and sends `pre_snapshot_scrub`, then exits. The
//! pre-snapshot hook (invoked by the supervisor before `Cmd::Snapshot`) calls
//! this so the live broker drops its in-RAM creds — a real socket round-trip,
//! NOT the old `| /bin/true` no-op (spec §4 / review fix).
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use tabbify_broker::creds::Creds;
use tabbify_broker::server::serve;
use tabbify_workspace_contract::{BROKER_SOCKET, PROJECTS_DIR};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if std::env::args().any(|a| a == "--scrub") {
        return run_scrub();
    }

    // §12 S1: the supervisor writes per-repo cap-URLs into this 0600 dir.
    let caps_dir = PathBuf::from("/run/tabbify/caps");
    let forge_admin = PathBuf::from("/run/tabbify/forge-admin");
    let creds = Creds::load(
        &caps_dir,
        if forge_admin.exists() {
            Some(forge_admin.as_path())
        } else {
            None
        },
    );

    serve(
        &PathBuf::from(BROKER_SOCKET),
        creds,
        PathBuf::from(PROJECTS_DIR),
    )
    .await
}

/// One-shot client: tell the live broker to drop its in-RAM creds.
fn run_scrub() -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(BROKER_SOCKET)?;
    stream.write_all(b"{\"kind\":\"pre_snapshot_scrub\"}\n")?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    if !line.contains("\"ok\":true") {
        anyhow::bail!("scrub failed: {line}");
    }
    println!("pre-snapshot: broker in-RAM creds dropped");
    Ok(())
}
