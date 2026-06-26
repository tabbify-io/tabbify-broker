//! Forgejo REST adapter. The broker holds the admin/owner token and mints
//! scoped per-user repos. It returns `ForgeRepoInfo` / PR / file-URL results —
//! NEVER the token. `forge_base` is the mesh-internal Forgejo URL (config).
//!
//! §12 S2: T1 owns ONLY `provision_repo` (create the repo in the user's org from
//! the admin token) — kept verbatim below. T5 ADDS the `ForgeClient`
//! (`ensure_scoped_token` + list/PR/file-url) in `client`, the agent-facing
//! handlers in `handler`, and the real `GitSessionEntry` push-cap in
//! `git_session` (the §12 S3 3-field shape).

pub mod client;
mod contents;
pub mod git_session;
pub mod handler;

pub use client::ForgeClient;
pub use contents::ForgeFile;
pub use git_session::{FORGE_PUSH_CAP_TTL, GitSessionEntry, GitSessions};
pub use handler::{
    ForgeContext, forge_file_url, forge_list_repos, forge_open_pr, register_forge_push_cap,
};

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};
use tabbify_workspace_contract::rpc::{ForgeProvisionReq, ForgeRepoInfo};

use crate::creds::Creds;

/// Forge connection config (mesh-internal URL + the user's org).
pub struct ForgeCfg {
    /// Mesh-internal Forgejo API base the broker calls (`TABBIFY_FORGE_URL`).
    pub base_url: String,
    /// The caller's OWN org slug (`TABBIFY_FORGE_ORG`, from the FC — never agent
    /// supplied), so §11.1 always resolves under this tenant.
    pub org: String,
    /// Externally shareable base baked into web links by `file_url`
    /// (`TABBIFY_FORGE_ROOT_URL`); defaults to `base_url` when unset.
    pub root_url: String,
}

impl ForgeCfg {
    /// Build from env (`TABBIFY_FORGE_URL`, `TABBIFY_FORGE_ORG`,
    /// `TABBIFY_FORGE_ROOT_URL`). When the URL/org are unset the forge is
    /// unconfigured and ops return `needs_credential`.
    pub fn from_env() -> Option<Self> {
        let base_url = std::env::var("TABBIFY_FORGE_URL").ok()?;
        let org = std::env::var("TABBIFY_FORGE_ORG").ok()?;
        let root_url = std::env::var("TABBIFY_FORGE_ROOT_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| base_url.clone());
        Some(Self { base_url, org, root_url })
    }
}

/// Create a repo in the user's forge org. Uses the admin token via the
/// `Authorization: token <…>` header; returns only the repo info.
pub async fn provision_repo(
    creds: &Creds,
    cfg: &ForgeCfg,
    req: &ForgeProvisionReq,
) -> Result<ForgeRepoInfo, CodeError> {
    let token = creds.forge_admin_token().ok_or_else(|| {
        CodeError::new(CodeErrorCode::NeedsCredential, "forge not provisioned")
    })?;
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/v1/orgs/{}/repos",
        cfg.base_url.trim_end_matches('/'),
        cfg.org
    );
    let body = serde_json::json!({
        "name": req.name,
        "private": req.private.unwrap_or(true),
        "description": req.description.clone().unwrap_or_default(),
        "auto_init": true,
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("token {token}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("forge: {e}")))?;
    if !resp.status().is_success() {
        let code = resp.status();
        // Honest taxonomy: a 4xx (e.g. name conflict / bad request) is the
        // agent's input problem (Invalid); a 5xx is a forge-side failure
        // (Internal). Never collapse both into Internal.
        let kind = if code.is_client_error() {
            CodeErrorCode::Invalid
        } else {
            CodeErrorCode::Internal
        };
        return Err(CodeError::new(
            kind,
            format!("forge create failed: {code}"),
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("forge json: {e}")))?;
    Ok(ForgeRepoInfo {
        name: req.name.clone(),
        full_name: v["full_name"].as_str().unwrap_or_default().to_string(),
        clone_url: v["clone_url"].as_str().unwrap_or_default().to_string(),
        web_url: v["html_url"].as_str().unwrap_or_default().to_string(),
        default_branch: v["default_branch"].as_str().unwrap_or("main").to_string(),
        private: v["private"].as_bool().unwrap_or(true),
    })
}
