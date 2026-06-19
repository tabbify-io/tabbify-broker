//! Broker-local mirror of the supervisor's git-proxy session registry (§12 S3).
//!
//! MIRRORS `tabbify_service_supervisor::api::GitSessionEntry` — keep in sync (S3).
//! The shape is the REAL 3-field entry (`upstream_url`, `token`, `expires_at:
//! Instant`), NOT the review's invented 2-field `ForgePushCap`. We mirror the
//! type here (rather than depend on the whole supervisor crate) because the
//! supervisor pulls Firecracker/Linux-only deps that do not cross-compile to
//! musl for the broker's in-FC gate. At wiring time the supervisor process holds
//! the REAL `GitSessions`; the broker's `register_forge_push_cap` registers an
//! entry of this identical shape into it. Verified against the supervisor source:
//!   tabbify-service-supervisor/src/api/git_proxy.rs:48-68 —
//!   `pub struct GitSessionEntry { pub upstream_url: String, pub token: String,
//!    pub expires_at: std::time::Instant }`
//!   `pub struct GitSessions(Mutex<HashMap<String, GitSessionEntry>>)`
//!   `pub fn register(&self, cap: String, entry: GitSessionEntry)`
//!   `lookup` returns `None` once `expires_at < Instant::now()`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default TTL of a forge push cap. The broker refreshes it on its own schedule
/// (mirrors the GitHub-token refresh); a real `expires_at` is REQUIRED — a
/// `GitSessionEntry` with an elapsed `expires_at` is rejected by `lookup`.
pub const FORGE_PUSH_CAP_TTL: Duration = Duration::from_secs(60 * 60);

/// One registered git-proxy session's access. The token is injected at the proxy
/// (`Basic x-access-token:<token>`), NEVER embedded in the URL or shown to the
/// agent.
pub struct GitSessionEntry {
    /// Provider clone URL WITHOUT credentials (the forge mesh clone URL).
    pub upstream_url: String,
    /// Short-lived scoped token; injected outside the VM, never logged.
    pub token: String,
    /// When this session's token expires; lookups after this instant return `None`.
    pub expires_at: Instant,
}

/// Capability → session registry. `Mutex<HashMap>` is fine: a handful of caps,
/// requests are seconds apart.
#[derive(Default)]
pub struct GitSessions(Mutex<HashMap<String, GitSessionEntry>>);

impl GitSessions {
    /// Register a capability with its session entry. Overwrites any existing
    /// entry for the same cap.
    pub fn register(&self, cap: String, entry: GitSessionEntry) {
        self.0.lock().expect("git sessions lock").insert(cap, entry);
    }

    /// Resolve a cap to its `(upstream_url, token)` — `None` if unknown or its
    /// token has expired (matching the supervisor's expiry semantics).
    #[must_use]
    pub fn lookup(&self, cap: &str) -> Option<(String, String)> {
        let guard = self.0.lock().expect("git sessions lock");
        let entry = guard.get(cap)?;
        if entry.expires_at < Instant::now() {
            return None;
        }
        Some((entry.upstream_url.clone(), entry.token.clone()))
    }

    /// Remove the capability from the registry (revoke access immediately).
    pub fn revoke(&self, cap: &str) {
        self.0.lock().expect("git sessions lock").remove(cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_entry_is_looked_up_until_expiry() {
        let sessions = GitSessions::default();
        sessions.register(
            "cap1".into(),
            GitSessionEntry {
                upstream_url: "http://forge.mesh/t_acme/app.git".into(),
                token: "scoped".into(),
                expires_at: Instant::now() + Duration::from_secs(60),
            },
        );
        let (url, tok) = sessions.lookup("cap1").expect("registered + unexpired");
        assert_eq!(url, "http://forge.mesh/t_acme/app.git");
        assert_eq!(tok, "scoped");
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let sessions = GitSessions::default();
        sessions.register(
            "cap2".into(),
            GitSessionEntry {
                upstream_url: "http://forge.mesh/t_acme/app.git".into(),
                token: "scoped".into(),
                // already in the past
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(sessions.lookup("cap2").is_none(), "expired entry must not resolve");
    }

    #[test]
    fn unknown_cap_is_none() {
        let sessions = GitSessions::default();
        assert!(sessions.lookup("nope").is_none());
    }
}
