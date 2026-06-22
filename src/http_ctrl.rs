//! Token-gated HTTP control listener on `:8732` (§12 S6, T4 IDE-remote dynamic
//! add-key). This is the POST-BOOT path that fills the audit gap: `tcli ssh <ws>
//! --add-key` makes node POST the laptop pubkey here, and the broker appends it
//! to `~agent/.ssh/authorized_keys` via the SAME validated [`add_ssh_key`] op the
//! unix socket already exposes.
//!
//! ## Authorization (the security invariant — the AGENT must NOT self-add keys)
//! Every request MUST carry `Authorization: Bearer <cap>` where `<cap>` equals
//! the broker-held "authorized-keys cap". That cap is written by the supervisor
//! into the off-env cap-file `/run/tabbify/caps/authkeys.cap` (0600, broker-uid)
//! AND returned to node in the workspace-create response. The broker reads the
//! cap-file (broker-uid) to validate; the AGENT uid CANNOT read the cap-file, so
//! the agent — though it can reach `[ula]:8732` from inside the FC — has no
//! token and gets a `401`. Only node (which received the cap over the trusted
//! node→supervisor channel) can authorize an add-key. No cap written → fail
//! closed (`401` for everyone).
//!
//! ## Why a hand-rolled HTTP/1.1 frame
//! The broker is a tiny privileged process; we keep it dep-light (no axum/hyper)
//! by parsing the one request shape we accept. The listener binds `0.0.0.0:8732`
//! inside the FC (the runner forwards `[app_ula]:8732 → guest_ip:8732`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::authorized_keys::add_ssh_key;
use crate::creds::{Creds, constant_time_eq};

/// The in-FC port the broker serves the token-gated add-key endpoint on. NOT a
/// frozen-contract value — an admin/control seam (§12 S6); the runner forwards
/// `[app_ula]:BROKER_CTRL_PORT → guest_ip:BROKER_CTRL_PORT`, and node dials the
/// same port (`tabbify-service-node` `ssh_tunnel::WORKSPACE_BROKER_CTRL_PORT`).
/// Flipping it here is the single point of change if it must move.
pub const BROKER_CTRL_PORT: u16 = 8732;

/// The add-key route this listener serves.
const AUTH_KEYS_PATH: &str = "/v1/authorized-keys";
/// The pre-snapshot scrub route (GAP#4). The supervisor's runner POSTs this from
/// the HOST (`guest_ip:8732`) IMMEDIATELY before pausing the VM for a Full
/// snapshot, so no live cap-URL / token survives into the warm-restore snapshot.
/// It is the HOST-reachable, broker-uid twin of the in-guest `tabbify-broker
/// --scrub` (the broker socket is broker-uid-only and unreachable from the host).
/// Unauthenticated by design: the op only DROPS the broker's own creds — an agent
/// hitting it can at worst self-DoS (the next git op returns `needs_credential`;
/// the supervisor re-writes fresh caps on warm restore), NEVER gain a capability.
/// It must NOT be gated on the authkeys cap (the runner does not carry that cap
/// host-side, and gating drop-only ops adds no security).
const PRE_SNAPSHOT_SCRUB_PATH: &str = "/v1/pre-snapshot-scrub";
/// The reserved cap-file name (under the caps dir) holding the authorized-keys
/// cap (the `:8732` bearer token). Written 0600 broker-uid by the supervisor's
/// runner; the agent uid cannot read it. Re-read fresh per request so an
/// init-order race / post-boot write is picked up with no restart, and a scrub
/// (which deletes the file) makes the next read `None` → fail closed.
const AUTHKEYS_CAP_FILE: &str = "authkeys.cap";

/// Read the current authorized-keys cap from `caps_dir/authkeys.cap`, trimmed.
/// `None` when the file is absent (no cap provisioned / scrubbed) or empty — the
/// authz then fails closed. Cheap (a tiny 0600 file); read fresh per request.
fn read_authkeys_cap(caps_dir: &Path) -> Option<String> {
    std::fs::read_to_string(caps_dir.join(AUTHKEYS_CAP_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
/// Cap on a request we will buffer (a pubkey line is ~hundreds of bytes; this is
/// generous but bounds an abusive client).
const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The parsed pieces of an incoming add-key request that the pure authz+handler
/// core needs. Extracted from the raw HTTP frame by [`parse_request`].
#[derive(Debug, Default)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    /// The `Authorization` header value, verbatim (e.g. `Bearer <cap>`), if any.
    pub authorization: Option<String>,
    pub body: String,
}

/// The HTTP outcome the core produces: a status code + a short text body. The
/// listener serializes this into a minimal HTTP/1.1 response.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpOutcome {
    pub status: u16,
    pub body: String,
}

impl HttpOutcome {
    fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
        }
    }
}

/// Pull the bearer token out of an `Authorization: Bearer <token>` value.
/// Case-insensitive on the `Bearer` scheme; returns the trimmed token, or `None`
/// when the header is absent or not a bearer credential.
fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let raw = authorization?.trim();
    let rest = raw.strip_prefix("Bearer ").or_else(|| {
        // Case-insensitive scheme match without allocating.
        let (scheme, rest) = raw.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(rest)
    })?;
    let tok = rest.trim();
    if tok.is_empty() { None } else { Some(tok) }
}

/// THE authz + handler core (pure, unit-tested). Given the currently-held
/// authorized-keys cap (`held_cap`, freshly resolved per request — `None` when no
/// cap-file exists or it was scrubbed) and a parsed request, decide the HTTP
/// outcome:
/// - wrong method/path → `404`/`405`;
/// - missing/blank/wrong bearer token, or NO cap held (fail closed) → `401`
///   (the agent path: it has no token and cannot read the cap-file);
/// - valid token + valid pubkey → append via [`add_ssh_key`] → `200`;
/// - valid token + malformed pubkey → `400` (the add_ssh_key validator rejects
///   injection / multi-line / unknown-algo).
///
/// `held_cap` is resolved fresh per request (the broker re-reads the 0600
/// cap-file), so an init-order race or a post-boot cap write is picked up with no
/// restart, and a scrub (which removes the file) makes this `None` → fail closed.
/// `add_key` is injected so the unit tests assert the append happens ONLY after
/// the token check passes (the agent can never reach the privileged op).
pub fn handle_add_key<F>(held_cap: Option<&str>, req: &ParsedRequest, add_key: F) -> HttpOutcome
where
    F: FnOnce(&str) -> Result<(), tabbify_workspace_contract::error::CodeError>,
{
    if req.path != AUTH_KEYS_PATH {
        return HttpOutcome::new(404, "not found");
    }
    if req.method != "POST" {
        return HttpOutcome::new(405, "method not allowed");
    }
    // AUTHORIZATION FIRST: validate the bearer token BEFORE touching the body or
    // the privileged op. The agent (no token) never gets past this line.
    let presented = bearer_token(req.authorization.as_deref());
    let authorized = match (held_cap, presented) {
        (Some(held), Some(tok)) => constant_time_eq(held.as_bytes(), tok.as_bytes()),
        // No cap held (none written / scrubbed) OR no token presented → reject.
        _ => false,
    };
    if !authorized {
        // Fail closed: no cap held, missing token, or wrong token all → 401.
        return HttpOutcome::new(401, "unauthorized");
    }
    // Body shape: `{ "public_key": "...", ... }` (node also sends `user`, which
    // the broker ignores — the login user is fixed to `agent`, the only sshd
    // AllowUsers account; accepting an arbitrary `user` would be a privilege
    // mistake). A legacy `pubkey` key is also accepted for robustness.
    let parsed: serde_json::Value = match serde_json::from_str(req.body.trim()) {
        Ok(v) => v,
        Err(_) => return HttpOutcome::new(400, "bad json body"),
    };
    let key = parsed
        .get("public_key")
        .or_else(|| parsed.get("pubkey"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if key.is_empty() {
        return HttpOutcome::new(400, "missing public_key");
    }
    match add_key(key) {
        Ok(()) => HttpOutcome::new(200, "ok"),
        Err(e) => {
            // The validated append rejects injection/garbage as `Invalid` (a 400
            // — the caller's bad input), anything else is a `500`.
            let status =
                if e.code == tabbify_workspace_contract::error::CodeErrorCode::Invalid {
                    400
                } else {
                    500
                };
            HttpOutcome::new(status, &e.message)
        }
    }
}

/// The reserved cred-file names removed by the pre-snapshot scrub (defence in
/// depth on top of the in-RAM drop): the per-repo cap-URLs (`*.url`), the §12-S6
/// authkeys cap (the `:8732` bearer token), and the forge-admin token. Mirrors
/// `scripts/pre-snapshot-scrub.sh` so a broker RESTART after a warm restore
/// re-reads nothing stale. The `*.url` files are enumerated (a glob); the named
/// ones are removed explicitly.
const SCRUBBED_CAP_FILES: &[&str] = &["authkeys.cap", "forge-admin.token"];

/// Remove the on-disk cred files under `caps_dir` (the tmpfs cap area). Best
/// effort: a missing file is fine (already absent / never written). Returns the
/// count removed — used only for the log line, never leaks a value. Runs as the
/// broker uid (the listener process), the only uid that can read/unlink the 0700
/// cap dir's 0600 files.
fn remove_cred_files(caps_dir: &Path) -> usize {
    let mut removed = 0usize;
    // Per-repo cap-URLs (`<repo>.url`).
    if let Ok(rd) = std::fs::read_dir(caps_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".url")
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    for f in SCRUBBED_CAP_FILES {
        if std::fs::remove_file(caps_dir.join(f)).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// THE pre-snapshot scrub core (GAP#4). Drops the broker's in-RAM creds
/// ([`Creds::scrub`]) AND removes the tmpfs cred files ([`remove_cred_files`]),
/// the SAME two halves `scripts/pre-snapshot-scrub.sh` performs. After this the
/// broker holds NOTHING, the `:8732` add-key endpoint fails closed (the authkeys
/// cap-file is gone → `None` per request), and a Full snapshot taken of the
/// paused VM freezes no live cap-URL / token. Always `200 ok` (a drop-only op
/// cannot meaningfully fail; a missing file is success).
pub fn handle_scrub(creds: &Arc<Mutex<Creds>>, req: &ParsedRequest, caps_dir: &Path) -> HttpOutcome {
    if req.path != PRE_SNAPSHOT_SCRUB_PATH {
        return HttpOutcome::new(404, "not found");
    }
    if req.method != "POST" {
        return HttpOutcome::new(405, "method not allowed");
    }
    creds.lock().unwrap().scrub();
    let removed = remove_cred_files(caps_dir);
    tracing::info!(removed, "pre-snapshot scrub: in-RAM creds dropped + cred files removed");
    HttpOutcome::new(200, "ok")
}

/// Parse a buffered HTTP/1.1 request into the pieces [`handle_add_key`] needs.
/// Minimal by design: request line + the `Authorization` header + the body after
/// the blank line. Returns `None` on a malformed frame (no request line).
pub fn parse_request(raw: &str) -> Option<ParsedRequest> {
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        // Tolerate bare-LF clients (no CRLF) — still extract the head.
        None => match raw.split_once("\n\n") {
            Some((h, b)) => (h, b),
            None => (raw, ""),
        },
    };
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    Some(ParsedRequest {
        method,
        path,
        authorization,
        body: body.to_owned(),
    })
}

/// Serve the `:8732` control endpoint until cancelled. Binds
/// `0.0.0.0:BROKER_CTRL_PORT` (the runner forwards the app-ULA here). Two routes:
/// - `POST /v1/authorized-keys` — token-gated add-key. The authorized-keys cap is
///   re-read FRESH from `caps_dir/authkeys.cap` (0600, broker-uid) per request —
///   so a post-boot/init-race cap write is honored with no restart, and the
///   pre-snapshot scrub (which deletes the file) makes the endpoint fail closed.
/// - `POST /v1/pre-snapshot-scrub` — GAP#4 drop-only scrub. Shares the SAME
///   `Arc<Mutex<Creds>>` the broker socket holds, so dropping in-RAM creds here is
///   process-wide (the socket's next git op sees nothing).
pub async fn serve(
    bind: SocketAddr,
    caps_dir: PathBuf,
    creds: Arc<Mutex<Creds>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, caps_dir = %caps_dir.display(), "broker :8732 control listener up (add-key token-gated + pre-snapshot-scrub)");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let caps_dir = caps_dir.clone();
        let creds = creds.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &caps_dir, &creds).await {
                tracing::debug!(error = %e, "broker :8732 conn ended");
            }
        });
    }
}

/// Read one request off the connection, route it (add-key vs scrub), write the
/// response.
async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    caps_dir: &Path,
    creds: &Arc<Mutex<Creds>>,
) -> anyhow::Result<()> {
    // Read until the header/body boundary, bounded by MAX_REQUEST_BYTES. The
    // request is tiny (one pubkey line); we read up to the cap then parse what we
    // have (no Content-Length streaming needed for this single small shape).
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= MAX_REQUEST_BYTES {
            break;
        }
        // Stop once we have a full head + at least the start of a body. A simple
        // heuristic: if we've seen the blank line and the socket has nothing
        // immediately more, the small body is already here.
        if find_body_boundary(&buf).is_some() {
            // Try a non-blocking peek: if no more bytes are pending, we're done.
            // Bounded extra read keeps a slow body from hanging forever.
            match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                stream.read(&mut chunk),
            )
            .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() >= MAX_REQUEST_BYTES {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        }
    }

    let raw = String::from_utf8_lossy(&buf);
    let outcome = match parse_request(&raw) {
        Some(req) if req.path == PRE_SNAPSHOT_SCRUB_PATH => {
            // GAP#4: drop-only scrub (no authz — see PRE_SNAPSHOT_SCRUB_PATH).
            handle_scrub(creds, &req, caps_dir)
        }
        Some(req) => {
            // Resolve the cap FRESH per request (0600 broker-uid file) — robust to
            // init order + dropped by the pre-snapshot scrub.
            let held = read_authkeys_cap(caps_dir);
            handle_add_key(held.as_deref(), &req, add_ssh_key)
        }
        None => HttpOutcome::new(400, "malformed request"),
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        outcome.status,
        reason(outcome.status),
        outcome.body.len(),
        outcome.body,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Index just past the head/body blank line, if present (CRLF or bare LF).
fn find_body_boundary(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
}

/// Minimal reason phrases for the statuses this endpoint emits.
const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};

    fn req(method: &str, path: &str, auth: Option<&str>, body: &str) -> ParsedRequest {
        ParsedRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            authorization: auth.map(str::to_owned),
            body: body.to_owned(),
        }
    }

    /// A correct bearer token + a valid pubkey → 200, and the append ran exactly
    /// once with that key.
    #[test]
    fn valid_token_and_key_appends_once_and_returns_200() {
        let called = Cell::new(0);
        let seen = std::cell::RefCell::new(String::new());
        let out = handle_add_key(
            Some("THE-CAP"),
            &req(
                "POST",
                AUTH_KEYS_PATH,
                Some("Bearer THE-CAP"),
                r#"{"user":"agent","public_key":"ssh-ed25519 AAAA user@laptop"}"#,
            ),
            |k| {
                called.set(called.get() + 1);
                *seen.borrow_mut() = k.to_owned();
                Ok(())
            },
        );
        assert_eq!(out.status, 200);
        assert_eq!(called.get(), 1);
        assert_eq!(&*seen.borrow(), "ssh-ed25519 AAAA user@laptop");
    }

    /// NO `Authorization` header → 401, and the privileged append is NEVER
    /// reached. This is the AGENT path: it can hit :8732 but holds no token.
    #[test]
    fn missing_token_is_401_and_never_appends() {
        let called = Cell::new(0);
        let out = handle_add_key(
            Some("THE-CAP"),
            &req(
                "POST",
                AUTH_KEYS_PATH,
                None,
                r#"{"public_key":"ssh-ed25519 AAAA evil@agent"}"#,
            ),
            |_| {
                called.set(called.get() + 1);
                Ok(())
            },
        );
        assert_eq!(out.status, 401, "no token must be unauthorized");
        assert_eq!(called.get(), 0, "add-key must NOT run without a valid token");
    }

    /// A WRONG bearer token → 401, append never reached.
    #[test]
    fn wrong_token_is_401_and_never_appends() {
        let called = Cell::new(0);
        let out = handle_add_key(
            Some("THE-CAP"),
            &req(
                "POST",
                AUTH_KEYS_PATH,
                Some("Bearer NOT-THE-CAP"),
                r#"{"public_key":"ssh-ed25519 AAAA x@y"}"#,
            ),
            |_| {
                called.set(called.get() + 1);
                Ok(())
            },
        );
        assert_eq!(out.status, 401);
        assert_eq!(called.get(), 0);
    }

    /// NO cap held (none written / scrubbed) → fail closed: even a "Bearer "
    /// request with some token is 401 (there is nothing to match).
    #[test]
    fn no_cap_held_fails_closed() {
        let called = Cell::new(0);
        let out = handle_add_key(
            None, // no authkeys cap present
            &req(
                "POST",
                AUTH_KEYS_PATH,
                Some("Bearer anything"),
                r#"{"public_key":"ssh-ed25519 AAAA x@y"}"#,
            ),
            |_| {
                called.set(called.get() + 1);
                Ok(())
            },
        );
        assert_eq!(out.status, 401, "no cap → fail closed");
        assert_eq!(called.get(), 0);
    }

    /// A prefix / longer guess of the cap is rejected (constant-time compare is
    /// exact, not a prefix match).
    #[test]
    fn prefix_or_longer_token_is_rejected() {
        for guess in ["THE-CA", "THE-CAPX", "", "the-cap"] {
            let out = handle_add_key(
                Some("THE-CAP"),
                &req(
                    "POST",
                    AUTH_KEYS_PATH,
                    Some(&format!("Bearer {guess}")),
                    r#"{"public_key":"ssh-ed25519 AAAA x@y"}"#,
                ),
                |_| Ok(()),
            );
            assert_eq!(out.status, 401, "guess {guess:?} must be 401");
        }
    }

    /// Valid token but a malformed pubkey → the validator's `Invalid` becomes a
    /// 400 (the caller's bad input, not a broker fault).
    #[test]
    fn valid_token_but_garbage_key_is_400() {
        let out = handle_add_key(
            Some("THE-CAP"),
            &req(
                "POST",
                AUTH_KEYS_PATH,
                Some("Bearer THE-CAP"),
                r#"{"public_key":"not-a-key blah"}"#,
            ),
            add_ssh_key_validate_only,
        );
        assert_eq!(out.status, 400);
    }

    /// Wrong path / method are rejected BEFORE any auth or append.
    #[test]
    fn wrong_route_is_404_or_405() {
        let g = handle_add_key(
            Some("THE-CAP"),
            &req("GET", AUTH_KEYS_PATH, Some("Bearer THE-CAP"), ""),
            |_| Ok(()),
        );
        assert_eq!(g.status, 405);
        let p = handle_add_key(
            Some("THE-CAP"),
            &req("POST", "/v1/other", Some("Bearer THE-CAP"), ""),
            |_| Ok(()),
        );
        assert_eq!(p.status, 404);
    }

    /// `read_authkeys_cap` reads + trims the cap-file, `None` on absent/empty.
    /// This is the per-request fresh read the listener uses (robust to init
    /// order; a scrub deletes the file → `None` → fail closed).
    #[test]
    fn read_authkeys_cap_reads_trims_and_handles_absence() {
        let td = tempfile::tempdir().unwrap();
        let caps = td.path().join("caps");
        std::fs::create_dir_all(&caps).unwrap();
        // Absent → None.
        assert_eq!(read_authkeys_cap(&caps), None);
        // Present + trimmed.
        std::fs::write(caps.join(AUTHKEYS_CAP_FILE), "  TOKEN-123 \n").unwrap();
        assert_eq!(read_authkeys_cap(&caps).as_deref(), Some("TOKEN-123"));
        // Empty file → None (fail closed).
        std::fs::write(caps.join(AUTHKEYS_CAP_FILE), "\n").unwrap();
        assert_eq!(read_authkeys_cap(&caps), None);
    }

    /// Case-insensitive `bearer` scheme; a non-bearer `Authorization` is ignored.
    #[test]
    fn bearer_scheme_is_case_insensitive_and_basic_is_ignored() {
        assert_eq!(bearer_token(Some("bearer abc")), Some("abc"));
        assert_eq!(bearer_token(Some("Bearer  abc  ")), Some("abc"));
        assert_eq!(bearer_token(Some("Basic abc")), None);
        assert_eq!(bearer_token(Some("Bearer ")), None);
        assert_eq!(bearer_token(None), None);
    }

    /// `parse_request` extracts the method/path/Authorization/body from a raw
    /// HTTP/1.1 frame (CRLF), case-insensitively on the header name.
    #[test]
    fn parse_request_extracts_fields() {
        let raw = "POST /v1/authorized-keys HTTP/1.1\r\nHost: x\r\nAUTHORIZATION: Bearer TOK\r\ncontent-type: application/json\r\n\r\n{\"public_key\":\"ssh-ed25519 AAAA u\"}";
        let p = parse_request(raw).unwrap();
        assert_eq!(p.method, "POST");
        assert_eq!(p.path, "/v1/authorized-keys");
        assert_eq!(p.authorization.as_deref(), Some("Bearer TOK"));
        assert!(p.body.contains("ssh-ed25519"));
    }

    /// GAP#4: the scrub core drops in-RAM creds AND removes the tmpfs cred files,
    /// returning 200. After it, `cap_names` is empty and the cred files are gone
    /// (so a broker restart re-reads nothing and the snapshot freezes no secret).
    #[test]
    fn scrub_drops_ram_creds_and_removes_cred_files_returns_200() {
        let td = tempfile::tempdir().unwrap();
        let caps = td.path().join("caps");
        std::fs::create_dir_all(&caps).unwrap();
        // A per-repo cap-URL, the authkeys cap, and the forge-admin token.
        std::fs::write(caps.join("app.url"), "http://h:8788/git/CAP\n").unwrap();
        std::fs::write(caps.join("authkeys.cap"), "THE-CAP\n").unwrap();
        std::fs::write(caps.join("forge-admin.token"), "ghs_secret\n").unwrap();
        let creds = Arc::new(Mutex::new(Creds::load(
            &caps,
            Some(caps.join("forge-admin.token").as_path()),
        )));
        // Pre: the broker holds the cap + forge.
        assert!(!creds.lock().unwrap().cap_names().is_empty());

        let out = handle_scrub(
            &creds,
            &req("POST", PRE_SNAPSHOT_SCRUB_PATH, None, ""),
            &caps,
        );
        assert_eq!(out.status, 200, "scrub must succeed");
        // In-RAM creds dropped.
        assert!(
            creds.lock().unwrap().cap_names().is_empty(),
            "scrub must drop the in-RAM creds so the snapshot freezes nothing"
        );
        // Cred files removed (defence in depth — a restart re-reads nothing).
        assert!(!caps.join("app.url").exists(), "*.url must be removed");
        assert!(!caps.join("authkeys.cap").exists(), "authkeys.cap must be removed");
        assert!(
            !caps.join("forge-admin.token").exists(),
            "forge-admin.token must be removed"
        );
    }

    /// The scrub route rejects the wrong method/path (defensive — the runner only
    /// ever POSTs the exact path).
    #[test]
    fn scrub_wrong_method_or_path_is_405_or_404() {
        let td = tempfile::tempdir().unwrap();
        let caps = td.path().join("caps");
        std::fs::create_dir_all(&caps).unwrap();
        let creds = Arc::new(Mutex::new(Creds::default()));
        let g = handle_scrub(&creds, &req("GET", PRE_SNAPSHOT_SCRUB_PATH, None, ""), &caps);
        assert_eq!(g.status, 405);
        let p = handle_scrub(&creds, &req("POST", "/v1/other", None, ""), &caps);
        assert_eq!(p.status, 404);
    }

    /// `remove_cred_files` is idempotent: removing from an empty/already-scrubbed
    /// dir is success (no panic), and a missing dir is tolerated.
    #[test]
    fn remove_cred_files_is_idempotent_and_tolerates_absence() {
        let td = tempfile::tempdir().unwrap();
        let caps = td.path().join("caps");
        std::fs::create_dir_all(&caps).unwrap();
        assert_eq!(remove_cred_files(&caps), 0, "empty dir → nothing removed");
        // A missing dir must not panic.
        let _ = remove_cred_files(&td.path().join("nope"));
    }

    /// Helper: validate a key like `add_ssh_key` but without touching the real
    /// `/home/agent/.ssh` path (the test runs off-FC). Mirrors the validator's
    /// `Invalid` rejection so the 400 mapping is exercised.
    fn add_ssh_key_validate_only(key: &str) -> Result<(), CodeError> {
        let ok = ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-"]
            .iter()
            .any(|p| key.starts_with(p));
        if ok && !key.contains('\n') {
            Ok(())
        } else {
            Err(CodeError::new(CodeErrorCode::Invalid, "unrecognised key type"))
        }
    }
}
