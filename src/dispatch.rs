//! Request dispatch. The wire request is the canonical `BrokerRequest`
//! (`request.rs`); each arm returns a serialized `CodeResponse<T>` line. The
//! forge list/pr/file-url arms are T5's to implement; here they return an HONEST
//! `internal "not implemented"` (never fabricated success / hardcoded-empty).

use std::path::Path;
use std::sync::{Arc, Mutex};

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};
use tabbify_workspace_contract::rpc::{
    CodeResponse, ForgeListReposResp, ForgePrResp, ForgeUrlResp, ListCapsResp,
};

use crate::authorized_keys::add_ssh_key;
use crate::creds::Creds;
use crate::forge::{provision_repo, ForgeCfg};
use crate::git_ops::run_git_op;
use crate::request::BrokerRequest;

/// Not-implemented placeholder for the forge arms T5 fills in: returns
/// `internal` with a clear message (NOT a fake success / empty list). When T5
/// lands `ensure_scoped_token` + these arms, it replaces each `not_impl` call.
fn not_impl<T: serde::Serialize>(what: &str) -> String {
    err_line::<T>(CodeError::new(
        CodeErrorCode::Internal,
        format!("{what} not implemented (T5 broker arm)"),
    ))
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
        // T5-owned arms: honest not-implemented until T5 lands them.
        Ok(BrokerRequest::ForgeList) => not_impl::<ForgeListReposResp>("forge_list"),
        Ok(BrokerRequest::ForgeOpenPr(_)) => not_impl::<ForgePrResp>("forge_open_pr"),
        Ok(BrokerRequest::ForgeFileUrl(_)) => not_impl::<ForgeUrlResp>("forge_file_url"),
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
