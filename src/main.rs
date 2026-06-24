//! Broker binary: load creds from the 0600 non-env files, then serve on
//! `BROKER_SOCKET`. Runs as the privileged `broker` uid (set by `/init`).
//!
//! `tabbify-broker --scrub` is a one-shot CLIENT mode: it connects to the
//! running broker's socket and sends `pre_snapshot_scrub`, then exits. The
//! pre-snapshot hook (invoked by the supervisor before `Cmd::Snapshot`) calls
//! this so the live broker drops its in-RAM creds — a real socket round-trip,
//! NOT the old `| /bin/true` no-op (spec §4 / review fix).
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tabbify_broker::creds::Creds;
use tabbify_broker::http_ctrl::{self, BROKER_CTRL_PORT};
use tabbify_broker::server::serve_shared;
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

    // §12 S1: the supervisor writes per-repo cap-URLs into this 0600 dir, and
    // the forge-admin creds blob as the reserved `forge-admin.token` cap-file
    // inside it (the caps scanner only consumes `*.url`, so this is ignored by
    // the git-cap scan and read directly below).
    let caps_dir = PathBuf::from("/run/tabbify/caps");
    let forge_admin = PathBuf::from("/run/tabbify/caps/forge-admin.token");
    let creds = Creds::load(
        &caps_dir,
        if forge_admin.exists() {
            Some(forge_admin.as_path())
        } else {
            None
        },
    );
    // ONE shared cred cell across BOTH listeners (the unix socket + the :8732 HTTP
    // control endpoint), so the pre-snapshot scrub drops the in-RAM creds
    // PROCESS-WIDE — the socket's next git op then sees nothing. (spec §4 / GAP#4).
    let creds = Arc::new(Mutex::new(creds));

    // The :8732 HTTP control endpoint (§12 S6 add-key + GAP#4 pre-snapshot-scrub).
    // Binds the guest's IPv4 eth0 (0.0.0.0) — the runner's L4 forwarder dials
    // guest_ip:8732 (IPv4) and bridges [app_ula]:8732 → here. add-key re-reads the
    // authkeys cap FRESH per request (0600, broker-uid) — robust to init order +
    // dropped by the scrub; the AGENT can reach the port but holds no token. The
    // scrub route shares the cred cell below so it drops the broker's RAM creds.
    let http_bind = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), BROKER_CTRL_PORT);
    let http_caps_dir = caps_dir.clone();
    let http_creds = creds.clone();
    let http = tokio::spawn(async move {
        if let Err(e) = http_ctrl::serve(http_bind, http_caps_dir, http_creds).await {
            tracing::error!(error = %e, "broker :8732 control listener exited");
        }
    });

    let socket_path = PathBuf::from(BROKER_SOCKET);
    let socket = serve_shared(&socket_path, creds, PathBuf::from(PROJECTS_DIR));

    // Run both concurrently; if the socket server returns (error/cancel), abort
    // the HTTP task and propagate.
    let result = socket.await;
    http.abort();
    result
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
