//! Unix-socket server. Binds `socket_path` 0600, one request per connection
//! (newline-delimited JSON in, one `CodeResponse` line out). The agent uid has
//! NO rwx on the socket (0600, broker-uid) — only a broker-uid client connects.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::creds::Creds;
use crate::dispatch::dispatch;

/// Serve broker RPC on `socket_path` until cancelled. Idempotent on a stale
/// socket file (removes it first), then chmods to 0600. `creds` is held behind
/// `Arc<Mutex<…>>` so the `pre_snapshot_scrub` op can drop the in-RAM secrets
/// process-wide before a Full snapshot (spec §4) — and so the `:8732` HTTP
/// control listener shares the SAME creds (a scrub drops the authkeys cap there
/// too, after which add-key fails closed).
///
/// Convenience wrapper that owns the `Creds` (legacy / test callers); the binary
/// uses [`serve_shared`] so it can hand the same `Arc<Mutex<Creds>>` to both the
/// socket server and the HTTP control listener.
pub async fn serve(
    socket_path: &Path,
    creds: Creds,
    projects_root: std::path::PathBuf,
) -> anyhow::Result<()> {
    serve_shared(socket_path, Arc::new(Mutex::new(creds)), projects_root).await
}

/// Serve broker RPC on `socket_path`, sharing `creds` with the caller (so the
/// `:8732` HTTP control listener can scrub the same state). See [`serve`].
pub async fn serve_shared(
    socket_path: &Path,
    creds: Arc<Mutex<Creds>>,
    projects_root: std::path::PathBuf,
) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(socket = %socket_path.display(), "broker listening (0600)");

    loop {
        let (stream, _) = listener.accept().await?;
        let creds = creds.clone();
        let projects = projects_root.clone();
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let reply = dispatch(&creds, &projects, &line).await;
            let _ = w.write_all(reply.as_bytes()).await;
        });
    }
}
