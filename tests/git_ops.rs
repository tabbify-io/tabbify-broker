//! Git op against a LOCAL bare repo standing in for the cap-URL remote, so the
//! test needs no network. We assert: push advances the remote, and the returned
//! output never contains a token-shaped secret.
use std::process::Command;
use tabbify_broker::creds::Creds;
use tabbify_broker::git_ops::run_git_op;
use tabbify_workspace_contract::rpc::{GitOp, GitOpReq};

fn sh(dir: &std::path::Path, args: &[&str]) {
    let ok = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .status()
        .unwrap()
        .success();
    assert!(ok, "command failed: {args:?}");
}

#[test]
fn push_advances_local_remote() {
    let td = tempfile::tempdir().unwrap();
    let bare = td.path().join("remote.git");
    let work = td.path().join("projects/demo");
    std::fs::create_dir_all(&work).unwrap();
    sh(td.path(), &["git", "init", "--bare", bare.to_str().unwrap()]);
    // Pin the branch name so the test is independent of the host's
    // `init.defaultBranch` (some boxes default to `main`, others `master`).
    sh(&work, &["git", "init", "-b", "master"]);
    sh(&work, &["git", "config", "user.email", "a@b.c"]);
    sh(&work, &["git", "config", "user.name", "t"]);
    std::fs::write(work.join("f.txt"), "hi").unwrap();
    sh(&work, &["git", "add", "."]);
    sh(&work, &["git", "commit", "-m", "init"]);
    sh(&work, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);

    // The broker uses the cap-URL as the remote; here the "cap-URL" is the bare path.
    let creds = Creds::default(); // git_cap_url None → broker uses the repo's own origin
    let res = run_git_op(
        &creds,
        td.path().join("projects").as_path(),
        &GitOpReq {
            repo: "demo".into(),
            op: GitOp::Push,
            git_ref: Some("master".into()),
        },
    )
    .unwrap();
    assert!(!res.output.contains("x-access-token"));

    // The push must actually have advanced the bare remote: its `master` ref now
    // resolves to the working copy's HEAD.
    let remote_head = Command::new("git")
        .args(["rev-parse", "master"])
        .current_dir(&bare)
        .output()
        .unwrap();
    assert!(remote_head.status.success(), "remote has no master ref");
    let remote_sha = String::from_utf8_lossy(&remote_head.stdout).trim().to_string();
    assert_eq!(Some(remote_sha), res.commit_sha);
}
