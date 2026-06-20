//! Credential custody. Loaded from the 0600 non-env files the SUPERVISOR writes
//! into the FC (§12 S1): one PER-REPO cap-URL file `/run/tabbify/caps/<repo>.url`
//! plus the optional forge-admin creds at `/run/tabbify/caps/forge-admin.token`
//! (the reserved cap-file name the supervisor writes). The cap-URL NEVER arrives via
//! env or `/init` (spec §4 line 63). The raw values NEVER leave this module
//! except as the remote on an outbound git/forge request the broker makes.

use std::collections::HashMap;
use std::path::Path;

/// The forge owner credentials the broker holds for THIS user's org (decrypted by
/// auth, carried by node, written to the 0600 non-env file by the supervisor —
/// §12 S1 / §4 / §11.0 D1). `admin_token` is the org-admin token (org-level
/// reads); `owner_user`/`owner_password` let the broker BasicAuth-mint the
/// per-org scoped push token (Forgejo restricts token minting to BasicAuth).
///
/// WIRE SHAPE PIN: the JSON keys MUST byte-match auth's `forge_admin::ForgeOwnerCreds`
/// — the same JSON crosses auth→node→supervisor→broker. (Independent crates; only
/// the JSON keys are the contract.)
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ForgeOwnerCreds {
    pub owner_user: String,
    pub owner_password: String,
    pub admin_token: String,
}

/// Held credentials. Cheap to clone (a handful of small strings); kept off the
/// agent uid (the cap dir + this process are broker-uid only).
#[derive(Clone, Default)]
pub struct Creds {
    /// `repo name` → cap-URL (`http://{host_ip}:8788/git/{cap}`). One per repo,
    /// written by the supervisor on workspace-create (§12 S1).
    git_caps: HashMap<String, String>,
    /// Bare org-admin token only (legacy single-string `/run/tabbify/forge-admin`
    /// file). Kept for `provision_repo`'s `forge_admin_token()` accessor.
    forge_admin_token: Option<String>,
    /// Full owner creds, when the supervisor wrote the JSON blob (the channel that
    /// enables `ensure_scoped_token`'s BasicAuth mint). `None` when only the bare
    /// admin token (or nothing) is present.
    forge_owner: Option<ForgeOwnerCreds>,
}

impl Creds {
    /// Load from the §12-S1 cap directory + the optional forge-admin file. A
    /// `<repo>.url` file maps repo `<repo>` → its cap-URL. Missing dir/files → no
    /// caps (the matching op then returns `needs_credential`). The reserved
    /// `authkeys.cap` file is NOT loaded here — the `:8732` HTTP endpoint
    /// (`http_ctrl`) re-reads it FRESH per request so an init-order race / a
    /// post-boot write is honored, and the scrub (file removal) fails it closed.
    pub fn load(caps_dir: &Path, forge_admin_path: Option<&Path>) -> Self {
        let mut git_caps = HashMap::new();
        if let Ok(rd) = std::fs::read_dir(caps_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(repo) = name.strip_suffix(".url") else {
                    continue;
                };
                if let Ok(url) = std::fs::read_to_string(entry.path()) {
                    let url = url.trim().to_string();
                    if !url.is_empty() {
                        git_caps.insert(repo.to_string(), url);
                    }
                }
            }
        }
        // The supervisor writes EITHER a JSON `{owner_user, owner_password,
        // admin_token}` blob (the full non-env channel, §12 S1 — enables the
        // BasicAuth scoped-token mint) OR a legacy bare admin-token string. Parse
        // the JSON first; fall back to treating the contents as a bare token.
        let raw = forge_admin_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let (forge_admin_token, forge_owner) = match raw {
            None => (None, None),
            Some(s) => match serde_json::from_str::<ForgeOwnerCreds>(&s) {
                Ok(creds) => (Some(creds.admin_token.clone()), Some(creds)),
                // Not JSON → a legacy bare admin token; no owner creds (no mint).
                Err(_) => (Some(s), None),
            },
        };
        Self {
            git_caps,
            forge_admin_token,
            forge_owner,
        }
    }

    /// The cap-URL (remote base) for `repo`, if the supervisor wrote one.
    pub fn git_cap_url(&self, repo: &str) -> Option<&str> {
        self.git_caps.get(repo).map(|s| s.as_str())
    }

    /// The forge admin token (used to mint scoped repos/tokens). Never returned
    /// to a caller — only used internally by `forge.rs`.
    pub fn forge_admin_token(&self) -> Option<&str> {
        self.forge_admin_token.as_deref()
    }

    /// The full forge owner creds (`{owner_user, owner_password, admin_token}`),
    /// present only when the supervisor wrote the JSON blob. Needed by
    /// `ensure_scoped_token` to BasicAuth-mint the scoped push token. Never
    /// returned to a caller — only used internally by `forge.rs`.
    pub fn forge_owner(&self) -> Option<&ForgeOwnerCreds> {
        self.forge_owner.as_ref()
    }

    /// Capability NAMES only — for `list_caps`. Values are never exposed. Each
    /// git cap is named `git:<repo>` (the repo, never the cap token).
    pub fn cap_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.git_caps.keys().map(|r| format!("git:{r}")).collect();
        if self.forge_admin_token.is_some() {
            names.push("forge".to_string());
        }
        names.sort();
        names
    }

    /// Drop EVERY in-RAM credential (overwrite the bytes, then clear). Called by
    /// the pre-snapshot scrub op so a Full snapshot freezes NO live cap-URL /
    /// token into RAM (spec §4). After this the broker holds nothing; the
    /// supervisor re-writes fresh cap files on warm restore and the broker
    /// reloads on the next op.
    pub fn scrub(&mut self) {
        // SAFETY: writing 0x00 to every byte keeps the buffer valid UTF-8 (NUL is
        // valid ASCII), so `as_bytes_mut` stays sound; we then drop the strings.
        for s in self.git_caps.values_mut() {
            unsafe {
                for b in s.as_bytes_mut() {
                    *b = 0;
                }
            }
        }
        if let Some(s) = self.forge_admin_token.as_mut() {
            unsafe {
                for b in s.as_bytes_mut() {
                    *b = 0;
                }
            }
        }
        if let Some(creds) = self.forge_owner.as_mut() {
            for s in [
                &mut creds.owner_user,
                &mut creds.owner_password,
                &mut creds.admin_token,
            ] {
                unsafe {
                    for b in s.as_bytes_mut() {
                        *b = 0;
                    }
                }
            }
        }
        self.git_caps.clear();
        self.forge_admin_token = None;
        self.forge_owner = None;
    }
}

/// Length-independent byte compare (no early exit on the first mismatch), so a
/// timing observation cannot reveal how many leading bytes of the secret a guess
/// matched. Unequal lengths still return `false` (the OR-folded `diff` is set by
/// the length mismatch), so this is safe for variable-length tokens. Shared by
/// the `:8732` HTTP authz path (`http_ctrl`) so both compares are constant-time.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        // Index past either end as 0 — keeps the loop count independent of where
        // the first mismatch is, while still folding length into `diff` above.
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}
