//! Append a laptop-user SSH public key to `~agent/.ssh/authorized_keys` (§12 S6,
//! for T4 IDE-remote). The broker uid owns this file; the agent uid cannot write
//! it, so the privileged broker mediates the append. Idempotent (no dup lines).

use std::io::Write;
use std::path::PathBuf;

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};

/// `agent`'s authorized_keys path (the workspace SSH login user).
const AGENT_AUTH_KEYS: &str = "/home/agent/.ssh/authorized_keys";

/// Validate then append `pubkey` to `agent`'s authorized_keys (production path).
pub fn add_ssh_key(pubkey: &str) -> Result<(), CodeError> {
    add_ssh_key_to(pubkey, std::path::Path::new(AGENT_AUTH_KEYS))
}

/// Inner, path-parameterised so it is unit-testable against a temp file. Rejects
/// anything that is not a single-line `ssh-…`/`ecdsa-…` key (no newlines / no
/// `command=` injection, recognised algo prefix); idempotent on a dup line.
pub fn add_ssh_key_to(pubkey: &str, path: &std::path::Path) -> Result<(), CodeError> {
    let key = pubkey.trim();
    if key.is_empty() || key.contains('\n') || key.contains('\r') {
        return Err(CodeError::new(CodeErrorCode::Invalid, "key must be one line"));
    }
    let ok_algo = ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"]
        .iter()
        .any(|p| key.starts_with(p));
    if !ok_algo {
        return Err(CodeError::new(
            CodeErrorCode::Invalid,
            "unrecognised key type",
        ));
    }
    let path = PathBuf::from(path);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == key) {
        return Ok(()); // idempotent
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("mkdir: {e}")))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("open: {e}")))?;
    writeln!(f, "{key}")
        .map_err(|e| CodeError::new(CodeErrorCode::Internal, format!("append: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tabbify_workspace_contract::error::CodeErrorCode;

    #[test]
    fn appends_valid_key_idempotently_and_rejects_garbage() {
        let td = tempfile::tempdir().unwrap();
        let ak = td.path().join("authorized_keys");
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 laptop";
        add_ssh_key_to(key, &ak).unwrap();
        add_ssh_key_to(key, &ak).unwrap(); // idempotent — no dup
        let body = std::fs::read_to_string(&ak).unwrap();
        assert_eq!(body.lines().filter(|l| l.trim() == key).count(), 1);
        // Injection / multi-line / unknown-algo are rejected.
        assert_eq!(
            add_ssh_key_to("ssh-ed25519 X\ncommand=\"rm -rf /\" ssh-rsa Y", &ak)
                .unwrap_err()
                .code,
            CodeErrorCode::Invalid
        );
        assert_eq!(
            add_ssh_key_to("not-a-key blah", &ak).unwrap_err().code,
            CodeErrorCode::Invalid
        );
    }
}
