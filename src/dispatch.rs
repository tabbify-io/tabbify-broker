//! Request dispatch. The wire request is the canonical `BrokerRequest`
//! (`request.rs`); each arm returns a serialized `CodeResponse<T>` line. The
//! forge list/pr/file-url arms (T5) are REAL: they build a `ForgeContext` from
//! the held owner creds + forge config and call the `forge::handler` functions,
//! returning the real `CodeResponse<T>` (never a fabricated success / empty).

use std::path::Path;
use std::sync::{Arc, Mutex};

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};
use tabbify_workspace_contract::rpc::{
    CodeResponse, ForgeListReposResp, ForgePrResp, ForgeUrlResp, ListCapsResp,
};

use crate::authorized_keys::add_ssh_key;
use crate::creds::Creds;
use crate::forge::{
    ForgeCfg, ForgeClient, ForgeContext, forge_file_url, forge_list_repos, forge_open_pr,
    provision_repo,
};
use crate::git_ops::run_git_op;
use crate::request::BrokerRequest;

/// Build the forge context (org + a `ForgeClient` with the held owner creds) for
/// THIS user's FC, or a `needs_credential` error when the forge is unconfigured
/// or the org was never provisioned (no owner creds in the non-env file). The
/// `org_slug` is the broker-held org (`ForgeCfg.org`, from the FC) — NEVER agent
/// supplied, so §11.1 resolves under the caller's OWN org only.
fn forge_context(creds: &Creds) -> Result<ForgeContext, CodeError> {
    let cfg = ForgeCfg::from_env()
        .ok_or_else(|| CodeError::new(CodeErrorCode::NeedsCredential, "forge not configured"))?;
    let owner = creds.forge_owner().ok_or_else(|| {
        CodeError::new(CodeErrorCode::NeedsCredential, "forge not provisioned")
    })?;
    Ok(ForgeContext {
        org_slug: cfg.org,
        client: ForgeClient::new(
            cfg.base_url,
            // The shareable web base = the forge base (mesh-internal) by default;
            // `file_url` only needs a string base to build links against.
            cfg.root_url,
            owner.admin_token.clone(),
            owner.owner_user.clone(),
            owner.owner_password.clone(),
        ),
    })
}

/// Dispatch a request to its handler, returning a serialized envelope line.
/// `creds` is shared + mutable so the pre-snapshot scrub can drop in-RAM secrets.
pub async fn dispatch(creds: &Arc<Mutex<Creds>>, projects_root: &Path, raw: &str) -> String {
    let parsed: Result<BrokerRequest, _> = serde_json::from_str(raw.trim());
    match parsed {
        Ok(BrokerRequest::ListCaps) => {
            let caps = creds.lock().unwrap().cap_names();
            line(&CodeResponse::ok(ListCapsResp { caps }))
        }
        Ok(BrokerRequest::GitOp(req)) => {
            // Snapshot the creds for the duration of the op (the git subprocess
            // reads only the cap-URL; lock is brief).
            let snapshot = creds.lock().unwrap().clone();
            match run_git_op(&snapshot, projects_root, &req) {
                Ok(res) => line(&CodeResponse::ok(res)),
                Err(e) => err_line::<tabbify_workspace_contract::rpc::GitOpResult>(e),
            }
        }
        Ok(BrokerRequest::ForgeProvision(req)) => {
            // `.clone()` drops the lock guard at the end of this statement, so the
            // mutex is NOT held across the `.await` below.
            let snapshot = creds.lock().unwrap().clone();
            match ForgeCfg::from_env() {
                Some(cfg) => match provision_repo(&snapshot, &cfg, &req).await {
                    Ok(info) => line(&CodeResponse::ok(info)),
                    Err(e) => err_line::<tabbify_workspace_contract::rpc::ForgeRepoInfo>(e),
                },
                None => err_line::<tabbify_workspace_contract::rpc::ForgeRepoInfo>(
                    CodeError::new(CodeErrorCode::NeedsCredential, "forge not configured"),
                ),
            }
        }
        // §12 S6: append a laptop pubkey to ~agent/.ssh/authorized_keys (T4).
        Ok(BrokerRequest::AddSshKey(req)) => match add_ssh_key(&req.pubkey) {
            Ok(()) => line(&CodeResponse::ok(ListCapsResp { caps: Vec::new() })),
            Err(e) => err_line::<ListCapsResp>(e),
        },
        // §4: drop ALL in-RAM creds so the Full snapshot freezes no secret.
        Ok(BrokerRequest::PreSnapshotScrub) => {
            creds.lock().unwrap().scrub();
            line(&CodeResponse::ok(ListCapsResp { caps: Vec::new() }))
        }
        // T5 forge arms (REAL): build the forge context from the held owner creds
        // + config, then call the real handler. A missing config / un-provisioned
        // org surfaces an honest `needs_credential`; forge failures surface
        // `internal`; a cross-tenant repo surfaces `forbidden`.
        Ok(BrokerRequest::ForgeList) => {
            let snapshot = creds.lock().unwrap().clone();
            match forge_context(&snapshot) {
                Ok(ctx) => line(&forge_list_repos(&ctx).await),
                Err(e) => err_line::<ForgeListReposResp>(e),
            }
        }
        Ok(BrokerRequest::ForgeOpenPr(req)) => {
            let snapshot = creds.lock().unwrap().clone();
            match forge_context(&snapshot) {
                Ok(ctx) => line(&forge_open_pr(&ctx, &req).await),
                Err(e) => err_line::<ForgePrResp>(e),
            }
        }
        Ok(BrokerRequest::ForgeFileUrl(req)) => {
            let snapshot = creds.lock().unwrap().clone();
            match forge_context(&snapshot) {
                Ok(ctx) => line(&forge_file_url(&ctx, &req).await),
                Err(e) => err_line::<ForgeUrlResp>(e),
            }
        }
        Err(e) => err_line::<serde_json::Value>(CodeError::new(
            CodeErrorCode::Invalid,
            format!("bad request: {e}"),
        )),
    }
}

fn line<T: serde::Serialize>(r: &CodeResponse<T>) -> String {
    format!("{}\n", serde_json::to_string(r).unwrap())
}

fn err_line<T: serde::Serialize>(e: CodeError) -> String {
    line(&CodeResponse::<T>::err(e))
}
