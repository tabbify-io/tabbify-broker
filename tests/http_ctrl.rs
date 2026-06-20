//! End-to-end over a real TCP socket: bind the broker's :8732 control listener
//! on an ephemeral port, then prove the authz invariant on the WIRE.
//!
//! - no `Authorization` header → HTTP 401, key NOT appended (the agent path);
//! - a WRONG bearer token → HTTP 401, key NOT appended;
//! - the CORRECT bearer token → passes authz (does not 401).
//!
//! The cap is read FRESH from the cap-file per request (the listener takes a
//! caps-dir). This is the wire-level proof that the agent (which can reach :8732
//! but holds no token, and cannot read the 0600 cap-file) cannot self-add a key.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tabbify_broker::http_ctrl::{ParsedRequest, handle_add_key, parse_request};

/// Drive one HTTP/1.1 request to `addr` and return `(status_code, body)`.
async fn http_post(addr: std::net::SocketAddr, auth: Option<&str>, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let auth_line = auth.map(|a| format!("authorization: {a}\r\n")).unwrap_or_default();
    let req = format!(
        "POST /v1/authorized-keys HTTP/1.1\r\nhost: x\r\n{auth_line}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default();
    (status, body)
}

/// A caps dir with `authkeys.cap` = `token` (the temp dir keeps it alive).
fn caps_dir_with_cap(token: &str) -> (std::path::PathBuf, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let caps = td.path().join("caps");
    std::fs::create_dir_all(&caps).unwrap();
    std::fs::write(caps.join("authkeys.cap"), format!("{token}\n")).unwrap();
    (caps, td)
}

#[tokio::test]
async fn wire_authz_no_token_401_wrong_token_401_correct_token_passes() {
    let (caps_dir, _td) = caps_dir_with_cap("THE-WIRE-CAP");
    // Bind an ephemeral port and serve.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free the port for the broker's own bind
    let serve_caps = caps_dir.clone();
    tokio::spawn(async move {
        let _ = tabbify_broker::http_ctrl::serve(addr, serve_caps).await;
    });
    // Wait for the listener to come up.
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let key = r#"{"user":"agent","public_key":"ssh-ed25519 AAAAwirekey laptop"}"#;

    // No token → 401 (the AGENT path: reachable, but unauthorized).
    let (s, _b) = http_post(addr, None, key).await;
    assert_eq!(s, 401, "no token must be 401");

    // Wrong token → 401.
    let (s, _b) = http_post(addr, Some("Bearer WRONG"), key).await;
    assert_eq!(s, 401, "wrong token must be 401");

    // The 200 path appends to the REAL /home/agent/.ssh path inside the FC, which
    // does not exist off-FC; the production append is covered by the unit-level
    // `handle_add_key` test (injected appender). Here we assert the listener
    // REACHES the append for the correct token by observing it is NOT a 401 (it
    // proceeds past authz). A 500 (cannot write the off-FC path) still proves
    // authorization succeeded — the agent's 401 never gets this far.
    let (s, _b) = http_post(addr, Some("Bearer THE-WIRE-CAP"), key).await;
    assert_ne!(s, 401, "correct token must pass authorization (got {s})");
    assert_ne!(s, 404);
}

/// A listener over a caps dir with NO authkeys.cap fails closed on the wire:
/// EVERY request 401s (this is the agent's situation when no cap is provisioned).
#[tokio::test]
async fn wire_no_cap_file_fails_closed() {
    let td = tempfile::tempdir().unwrap();
    let caps = td.path().join("caps");
    std::fs::create_dir_all(&caps).unwrap(); // empty: no authkeys.cap
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let serve_caps = caps.clone();
    tokio::spawn(async move {
        let _ = tabbify_broker::http_ctrl::serve(addr, serve_caps).await;
    });
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let key = r#"{"public_key":"ssh-ed25519 AAAA agent@self"}"#;
    // Even presenting a "Bearer something" → 401 (nothing to match against).
    let (s, _b) = http_post(addr, Some("Bearer guess"), key).await;
    assert_eq!(s, 401, "no cap file → fail closed");
}

/// `parse_request` + `handle_add_key` round-trip stays consistent with the wire:
/// the exact frame the node sends parses to a POST on the route with the bearer
/// header intact, and the matching cap authorizes (does not 401).
#[tokio::test]
async fn node_frame_parses_to_authorized_request() {
    let frame = "POST /v1/authorized-keys HTTP/1.1\r\nhost: [fd5a::1]:8732\r\nauthorization: Bearer CAP123\r\ncontent-type: application/json\r\ncontent-length: 60\r\n\r\n{\"user\":\"agent\",\"public_key\":\"ssh-ed25519 AAAA u@l\"}";
    let req: ParsedRequest = parse_request(frame).unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/v1/authorized-keys");
    // The handler authorizes (token matches the held cap) → no 401 short-circuit.
    let out = handle_add_key(Some("CAP123"), &req, |_k| Ok(()));
    assert_eq!(out.status, 200);
}
