//! Creds load from the §12-S1 0600 cap DIR (one `<repo>.url` per repo);
//! `cap_names` lists NAMES only (never a value). The cap-URL never comes from
//! env — only from `/run/tabbify/caps/<repo>.url` written by the supervisor.
use std::fs;
use tabbify_broker::creds::Creds;

fn caps_dir_with(repo: &str, url: &str) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    let caps = td.path().join("caps");
    fs::create_dir_all(&caps).unwrap();
    fs::write(caps.join(format!("{repo}.url")), format!("{url}\n")).unwrap();
    td
}

#[test]
fn loads_per_repo_cap_url_and_lists_names_only() {
    let td = caps_dir_with("demo", "http://172.31.0.1:8788/git/SECRETCAP");
    let creds = Creds::load(&td.path().join("caps"), None);
    assert_eq!(
        creds.git_cap_url("demo"),
        Some("http://172.31.0.1:8788/git/SECRETCAP")
    );
    let names = creds.cap_names();
    assert!(names.contains(&"git:demo".to_string()));
    // No value (the cap token) ever appears in the names list.
    assert!(names.iter().all(|n| !n.contains("SECRETCAP")));
}

#[test]
fn absent_dir_yields_no_caps() {
    let td = tempfile::tempdir().unwrap();
    let creds = Creds::load(&td.path().join("nope"), None);
    assert!(creds.cap_names().is_empty());
    assert!(creds.git_cap_url("demo").is_none());
}

#[test]
fn scrub_drops_all_in_ram_creds() {
    let td = caps_dir_with("demo", "http://172.31.0.1:8788/git/SECRETCAP");
    let mut creds = Creds::load(&td.path().join("caps"), None);
    assert!(creds.git_cap_url("demo").is_some());
    creds.scrub();
    // After scrub the broker holds NOTHING — a Full snapshot freezes no secret.
    assert!(creds.git_cap_url("demo").is_none());
    assert!(creds.cap_names().is_empty());
}
