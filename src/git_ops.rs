//! Git operation execution. The broker runs git as a subprocess in the repo's
//! working copy (`<projects>/<repo>`), pushing/pulling against the cap-URL
//! remote. The cap-URL carries the capability, NOT a provider token — the
//! supervisor's git-proxy injects the real token OUTSIDE the VM. Output is
//! sanitized so no credential-shaped string is ever returned to the agent.

use std::path::{Component, Path};
use std::process::Command;

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};
use tabbify_workspace_contract::rpc::{GitOp, GitOpReq, GitOpResult};

use crate::creds::Creds;

/// Validate the repo name is a single confined segment (no traversal/separator).
/// The broker is a SEPARATE process from the codeservice (it cannot import the
/// codeservice's `paths`), so it enforces the same one-segment invariant here —
/// the only confinement check on the broker side, applied to EVERY git op.
fn safe_repo(repo: &str) -> Result<(), CodeError> {
    if repo.is_empty() {
        return Err(CodeError::new(CodeErrorCode::Invalid, "repo is required"));
    }
    let mut comps = Path::new(repo).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(s)), None) if s == repo => Ok(()),
        _ => Err(CodeError::new(CodeErrorCode::Forbidden, "invalid repo")),
    }
}

/// Run a git op for `repo` under `projects_root`. The per-repo cap-URL (when the
/// supervisor wrote one, §12 S1) is the push/fetch remote; otherwise the repo's
/// own `origin` is used (test path).
pub fn run_git_op(
    creds: &Creds,
    projects_root: &Path,
    req: &GitOpReq,
) -> Result<GitOpResult, CodeError> {
    safe_repo(&req.repo)?;
    let work = projects_root.join(&req.repo);

    let remote: String = match creds.git_cap_url(&req.repo) {
        // The cap-URL is already repo-scoped (`…/git/{cap}`); use it as-is.
        Some(url) => url.trim_end_matches('/').to_string(),
        None => "origin".to_string(),
    };

    let args: Vec<String> = match req.op {
        GitOp::Push => {
            let mut a = vec!["push".to_string(), remote.clone()];
            if let Some(r) = &req.git_ref {
                a.push(r.clone());
            }
            a
        }
        GitOp::Fetch => {
            let mut a = vec!["fetch".to_string(), remote.clone()];
            if let Some(r) = &req.git_ref {
                a.push(r.clone());
            }
            a
        }
        GitOp::Clone => vec![
            "clone".to_string(),
            remote.clone(),
            work.to_string_lossy().into_owned(),
        ],
    };

    // Clone runs in projects_root; push/fetch run in the working copy.
    let cwd = if matches!(req.op, GitOp::Clone) {
        projects_root
    } else {
        &work
    };
    let out = Command::new("git")
        .args(&args)
        .current_dir(cwd)
        .output()
        .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("git spawn: {e}")))?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&out.stdout));
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    let sanitized = sanitize(&combined, creds.git_cap_url(&req.repo));

    if !out.status.success() {
        return Err(CodeError::new(
            CodeErrorCode::Internal,
            format!("git {:?} failed: {sanitized}", req.op),
        ));
    }

    let commit_sha = head_sha(&work);
    Ok(GitOpResult {
        commit_sha,
        output: sanitized,
    })
}

/// Strip any occurrence of the cap-URL (and a generic token marker) from output.
fn sanitize(s: &str, cap_url: Option<&str>) -> String {
    let mut out = s.to_string();
    if let Some(url) = cap_url {
        out = out.replace(url, "[remote]");
    }
    out.replace("x-access-token", "[redacted]")
}

/// Best-effort `HEAD` sha of the working copy (None if not a repo yet).
fn head_sha(work: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(work)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}
