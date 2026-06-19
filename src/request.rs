//! The canonical broker wire request (§12 S2 — T1-owned). Tag-discriminated on
//! `kind`; payloads are the frozen contract types. Serializable (codeservice
//! client side) AND deserializable (broker side) so the seam is compile-checked.

use serde::{Deserialize, Serialize};
use tabbify_workspace_contract::rpc::{ForgeFileUrlReq, ForgeOpenPrReq, ForgeProvisionReq, GitOpReq};

/// One broker request, tag-discriminated on `kind` (`git_op`, `list_caps`,
/// `forge_provision`, `forge_list`, `forge_open_pr`, `forge_file_url`,
/// `add_ssh_key`, `pre_snapshot_scrub`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrokerRequest {
    GitOp(GitOpReq),
    ListCaps,
    ForgeProvision(ForgeProvisionReq),
    /// T5 adds the handler arm; declared here so the typed client forwards it.
    ForgeList,
    ForgeOpenPr(ForgeOpenPrReq),
    ForgeFileUrl(ForgeFileUrlReq),
    /// §12 S6 (for T4 IDE-remote): append a laptop-user's SSH public key to
    /// `~agent/.ssh/authorized_keys`. The node calls this (the agent uid cannot
    /// — only the broker uid may write agent's authorized_keys). Idempotent.
    AddSshKey(AddSshKeyReq),
    /// Drop ALL in-RAM creds before a Full snapshot freezes them (spec §4). The
    /// supervisor sends this over the socket immediately before `Cmd::Snapshot`.
    PreSnapshotScrub,
}

/// `add_ssh_key{pubkey}` — one OpenSSH `authorized_keys` line for the workspace
/// SSH login user (`agent`). Validated server-side before it is appended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSshKeyReq {
    pub pubkey: String,
}
