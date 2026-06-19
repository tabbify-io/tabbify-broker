//! Credential custody. Loaded from the 0600 non-env files the SUPERVISOR writes
//! into the FC (§12 S1): one PER-REPO cap-URL file `/run/tabbify/caps/<repo>.url`
//! plus an optional `/run/tabbify/forge-admin`. The cap-URL NEVER arrives via
//! env or `/init` (spec §4 line 63). The raw values NEVER leave this module
//! except as the remote on an outbound git/forge request the broker makes.

use std::collections::HashMap;
use std::path::Path;

/// Held credentials. Cheap to clone (a handful of small strings); kept off the
/// agent uid (the cap dir + this process are broker-uid only).
#[derive(Clone, Default)]
pub struct Creds {
    /// `repo name` → cap-URL (`http://{host_ip}:8788/git/{cap}`). One per repo,
    /// written by the supervisor on workspace-create (§12 S1).
    git_caps: HashMap<String, String>,
    forge_admin_token: Option<String>,
}

impl Creds {
    /// Load from the §12-S1 cap directory + the optional forge-admin file. A
    /// `<repo>.url` file maps repo `<repo>` → its cap-URL. Missing dir/files →
    /// no caps (the matching op then returns `needs_credential`).
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
        let forge_admin_token = forge_admin_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            git_caps,
            forge_admin_token,
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
        self.git_caps.clear();
        self.forge_admin_token = None;
    }
}
