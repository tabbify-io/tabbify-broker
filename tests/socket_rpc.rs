//! End-to-end socket RPC: bind the broker server on a temp socket, send a
//! framed `list_caps` request, assert the `CodeResponse` reply lists NAMES only
//! and the socket mode is 0600.
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use tabbify_broker::creds::Creds;
use tabbify_broker::server::serve;

#[tokio::test]
async fn list_caps_round_trip_and_socket_is_0600() {
    let td = tempfile::tempdir().unwrap();
    let sock = td.path().join("broker.sock");
    let caps = td.path().join("caps");
    std::fs::create_dir_all(&caps).unwrap();
    std::fs::write(caps.join("demo.url"), "http://172.31.0.1:8788/git/CAP\n").unwrap();
    let creds = Creds::load(&caps, None);
    let projects = td.path().join("projects");
    std::fs::create_dir_all(&projects).unwrap();

    let sock2 = sock.clone();
    tokio::spawn(async move { serve(&sock2, creds, projects).await.unwrap() });
    // wait for bind
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be 0600");

    let stream = UnixStream::connect(&sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    w.write_all(b"{\"kind\":\"list_caps\"}\n").await.unwrap();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["ok"], true);
    let caps = v["result"]["caps"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "git:demo"));
    assert!(!line.contains("CAP"));

    // pre_snapshot_scrub drops the in-RAM cap; a subsequent list_caps is empty.
    let s2 = UnixStream::connect(&sock).await.unwrap();
    let (_r2, mut w2) = s2.into_split();
    w2.write_all(b"{\"kind\":\"pre_snapshot_scrub\"}\n")
        .await
        .unwrap();
    // (one request per connection — open a fresh one to verify the effect)
    let s3 = UnixStream::connect(&sock).await.unwrap();
    let (r3, mut w3) = s3.into_split();
    w3.write_all(b"{\"kind\":\"list_caps\"}\n").await.unwrap();
    let mut line3 = String::new();
    BufReader::new(r3).read_line(&mut line3).await.unwrap();
    let v3: serde_json::Value = serde_json::from_str(&line3).unwrap();
    assert!(
        v3["result"]["caps"].as_array().unwrap().is_empty(),
        "scrub must drop the in-RAM cap so the snapshot freezes nothing"
    );
}

#[tokio::test]
async fn forge_list_arm_is_honest_not_implemented() {
    // T5 owns the forge_list/open_pr/file_url handler arms. Until then they must
    // return an HONEST error (internal, "not implemented") — never a fake
    // success / empty list. This guards the §12 S2 split.
    let td = tempfile::tempdir().unwrap();
    let sock = td.path().join("broker.sock");
    let caps = td.path().join("caps");
    std::fs::create_dir_all(&caps).unwrap();
    let creds = Creds::load(&caps, None);
    let projects = td.path().join("projects");
    std::fs::create_dir_all(&projects).unwrap();

    let sock2 = sock.clone();
    tokio::spawn(async move { serve(&sock2, creds, projects).await.unwrap() });
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let stream = UnixStream::connect(&sock).await.unwrap();
    let (r, mut w) = stream.into_split();
    w.write_all(b"{\"kind\":\"forge_list\"}\n").await.unwrap();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["ok"], false, "forge_list is not implemented yet (T5)");
    assert_eq!(v["error"]["code"], "internal");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not implemented"),
        "must be an HONEST not-implemented, got: {line}"
    );
}
