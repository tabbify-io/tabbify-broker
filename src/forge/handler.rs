//! Broker forge handlers (T5 additive surface, §12 S2):
//! - `forge_list_repos`  → repos in the caller's own org (human visibility).
//! - `forge_open_pr`     → open a PR (returns the shareable `web_url`).
//! - `forge_file_url`    → build a shareable file/line link.
//! - `register_forge_push_cap` → register a REAL `GitSessionEntry` (D1 push):
//!   the broker mints the scoped token (`ForgeClient::ensure_scoped_token`),
//!   builds a 256-bit cap-key + a 3-field entry with a real TTL, and registers it
//!   so the guest pushes tokenlessly while the token is injected OUTSIDE the VM.
//!
//! §11.1: every op resolves the repo under `ctx.org_slug` (the caller's OWN org,
//! derived from the FC — never agent-supplied). A repo name that would reference
//! another org → `Forbidden`.

use std::time::Instant;

use tabbify_workspace_contract::error::{CodeError, CodeErrorCode};
use tabbify_workspace_contract::rpc::{
    CodeResponse, ForgeFileUrlReq, ForgeListReposResp, ForgeOpenPrReq, ForgePrResp, ForgeUrlResp,
};

use crate::forge::client::ForgeClient;
use crate::forge::git_session::{FORGE_PUSH_CAP_TTL, GitSessionEntry, GitSessions};

/// The forge context the broker holds for THIS user's FC: the user's OWN org slug
/// + a live `ForgeClient` (owner creds already loaded from the non-env file).
pub struct ForgeContext {
    pub org_slug: String,
    pub client: ForgeClient,
}

/// Generate a 256-bit (64-hex) cap-key, same shape as the supervisor's
/// `dev_sessions::generate_cap` (blake3 over the binding + 2 fresh v4 UUIDs).
fn generate_forge_cap(org: &str, repo: &str) -> String {
    let salt_a = uuid::Uuid::new_v4();
    let salt_b = uuid::Uuid::new_v4();
    let input = format!("{org}/{repo}:{salt_a}:{salt_b}");
    hex::encode(blake3::hash(input.as_bytes()).as_bytes())
}

/// Reject a repo that does not resolve under the caller's own org (§11.1). The
/// agent supplies a bare repo NAME (contract `ForgeOpenPrReq.repo` etc.); if it
/// ever carries an `org/` prefix, it MUST be this caller's org.
fn ensure_same_tenant(ctx: &ForgeContext, repo: &str) -> Result<String, CodeError> {
    match repo.split_once('/') {
        None => Ok(repo.to_owned()),
        Some((org, name)) if org == ctx.org_slug => Ok(name.to_owned()),
        Some(_) => Err(CodeError::new(
            CodeErrorCode::Forbidden,
            "forge repo resolves under another org — cross-tenant access forbidden",
        )),
    }
}

fn internal(e: impl std::fmt::Display) -> CodeError {
    CodeError::new(CodeErrorCode::Internal, format!("forge: {e}"))
}

/// `forge_list_repos` — the caller's OWN org repos. Real data or a real error;
/// never a hardcoded empty list.
pub async fn forge_list_repos(ctx: &ForgeContext) -> CodeResponse<ForgeListReposResp> {
    match ctx.client.list_org_repos(&ctx.org_slug).await {
        Ok(repos) => CodeResponse::ok(ForgeListReposResp { repos }),
        Err(e) => CodeResponse::err(internal(e)),
    }
}

/// `forge_open_pr` — open a PR in the caller's own org (§11.1 guarded).
pub async fn forge_open_pr(ctx: &ForgeContext, req: &ForgeOpenPrReq) -> CodeResponse<ForgePrResp> {
    let repo = match ensure_same_tenant(ctx, &req.repo) {
        Ok(r) => r,
        Err(e) => return CodeResponse::err(e),
    };
    // Default base = the repo's default branch when omitted.
    let base = match &req.base {
        Some(b) => b.clone(),
        None => match ctx.client.default_branch(&ctx.org_slug, &repo).await {
            Ok(b) => b,
            Err(e) => return CodeResponse::err(internal(e)),
        },
    };
    match ctx
        .client
        .open_pr(&ctx.org_slug, &repo, &req.title, &req.head, &base, req.body.as_deref())
        .await
    {
        Ok(pr) => CodeResponse::ok(pr),
        Err(e) => CodeResponse::err(internal(e)),
    }
}

/// `forge_file_url` — a shareable web link (§11.1 guarded). Defaults `ref` to the
/// repo's default branch.
pub async fn forge_file_url(
    ctx: &ForgeContext,
    req: &ForgeFileUrlReq,
) -> CodeResponse<ForgeUrlResp> {
    let repo = match ensure_same_tenant(ctx, &req.repo) {
        Ok(r) => r,
        Err(e) => return CodeResponse::err(e),
    };
    let git_ref = match &req.git_ref {
        Some(r) => r.clone(),
        None => match ctx.client.default_branch(&ctx.org_slug, &repo).await {
            Ok(b) => b,
            Err(e) => return CodeResponse::err(internal(e)),
        },
    };
    CodeResponse::ok(ctx.client.file_url(&ctx.org_slug, &repo, &git_ref, &req.path))
}

/// Mint the scoped token + register a REAL `GitSessionEntry` so the guest pushes
/// tokenlessly (D1). Returns the cap-key the broker hands to the guest as the
/// tokenless remote `http://{host_ip}:8788/git/{cap}`. §11.1 guarded.
pub async fn register_forge_push_cap(
    sessions: &GitSessions,
    ctx: &ForgeContext,
    repo: &str,
    clone_url: &str,
) -> Result<String, CodeError> {
    let repo = ensure_same_tenant(ctx, repo)?;
    let token = ctx
        .client
        .ensure_scoped_token(&format!("broker-push-{}-{repo}", ctx.org_slug))
        .await
        .map_err(internal)?;
    let cap = generate_forge_cap(&ctx.org_slug, &repo);
    sessions.register(
        cap.clone(),
        GitSessionEntry {
            upstream_url: clone_url.to_owned(),
            token, // the scoped secret — injected at the proxy, NEVER in the URL
            expires_at: Instant::now() + FORGE_PUSH_CAP_TTL,
        },
    );
    Ok(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ctx(uri: String, org: &str) -> ForgeContext {
        ForgeContext {
            org_slug: org.into(),
            client: ForgeClient::new(
                uri,
                "http://forge.mesh".into(),
                "admintok".into(),
                format!("{org}-bot"),
                "ownerpw".into(),
            ),
        }
    }

    #[test]
    fn cross_tenant_repo_is_forbidden() {
        let c = ctx("http://unused".into(), "t_acme");
        // bare name OK
        assert!(ensure_same_tenant(&c, "app").is_ok());
        // own-org prefix OK, stripped to bare name
        assert_eq!(ensure_same_tenant(&c, "t_acme/app").unwrap(), "app");
        // another org → Forbidden (NOT Internal, NOT silent success)
        let err = ensure_same_tenant(&c, "t_evil/app").unwrap_err();
        assert_eq!(err.code, CodeErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn list_repos_returns_real_data_not_empty_stub() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/orgs/t_acme/repos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                "name": "app", "full_name": "t_acme/app",
                "clone_url": "http://forge.mesh/t_acme/app.git",
                "html_url": "http://forge.mesh/t_acme/app",
                "default_branch": "main", "private": true
            }])))
            .mount(&srv)
            .await;
        let resp = forge_list_repos(&ctx(srv.uri(), "t_acme")).await.into_result().unwrap();
        assert_eq!(resp.repos.len(), 1);
        assert_eq!(resp.repos[0].full_name, "t_acme/app");
    }

    #[tokio::test]
    async fn open_pr_in_another_org_is_forbidden_before_any_call() {
        // No mock mounted → if the guard fails, the call would error differently.
        let c = ctx("http://127.0.0.1:1".into(), "t_acme");
        let req = ForgeOpenPrReq {
            repo: "t_evil/app".into(),
            title: "x".into(),
            head: "f".into(),
            base: Some("main".into()),
            body: None,
        };
        let err = forge_open_pr(&c, &req).await.into_result().unwrap_err();
        assert_eq!(err.code, CodeErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn open_pr_in_own_org_maps_to_pr_resp() {
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/repos/t_acme/app/pulls"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 3, "html_url": "http://forge.mesh/t_acme/app/pulls/3"
            })))
            .mount(&srv)
            .await;
        let req = ForgeOpenPrReq {
            repo: "app".into(),
            title: "t".into(),
            head: "feat".into(),
            base: Some("main".into()),
            body: None,
        };
        let pr = forge_open_pr(&ctx(srv.uri(), "t_acme"), &req).await.into_result().unwrap();
        assert_eq!(pr.number, 3);
        assert_eq!(pr.web_url, "http://forge.mesh/t_acme/app/pulls/3");
    }

    #[tokio::test]
    async fn file_url_in_another_org_is_forbidden() {
        let req = ForgeFileUrlReq {
            repo: "t_evil/app".into(),
            path: "lib.rs".into(),
            git_ref: Some("main".into()),
        };
        let err = forge_file_url(&ctx("http://unused".into(), "t_acme"), &req)
            .await
            .into_result()
            .unwrap_err();
        assert_eq!(err.code, CodeErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn file_url_with_explicit_ref_needs_no_network() {
        // base "http://127.0.0.1:1" would fail on any HTTP call — proving the
        // explicit-ref path is a pure string build.
        let req = ForgeFileUrlReq {
            repo: "app".into(),
            path: "/src/lib.rs".into(),
            git_ref: Some("main".into()),
        };
        let url = forge_file_url(&ctx("http://127.0.0.1:1".into(), "t_acme"), &req)
            .await
            .into_result()
            .unwrap();
        assert_eq!(url.web_url, "http://forge.mesh/t_acme/app/src/main/src/lib.rs");
    }

    #[tokio::test]
    async fn register_push_cap_mints_token_and_registers_real_entry() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&srv)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "name": "broker-push-t_acme-app", "sha1": "scoped_tok_xyz"
            })))
            .mount(&srv)
            .await;

        let sessions = GitSessions::default();
        let cap = register_forge_push_cap(
            &sessions,
            &ctx(srv.uri(), "t_acme"),
            "app",
            "http://forge.mesh/t_acme/app.git",
        )
        .await
        .unwrap();
        assert_eq!(cap.len(), 64, "cap-key is 256-bit (64 hex chars)");
        // The entry is registered with the scoped token + a future expiry, so
        // `lookup` returns it (proves the 3-field shape is real, not a 2-field stub).
        let (upstream, token) = sessions.lookup(&cap).expect("registered + unexpired");
        assert_eq!(upstream, "http://forge.mesh/t_acme/app.git");
        assert_eq!(token, "scoped_tok_xyz");
        assert!(!upstream.contains("scoped_tok_xyz"), "token never embedded in the URL");
    }

    #[tokio::test]
    async fn register_push_cap_in_another_org_is_forbidden() {
        let sessions = GitSessions::default();
        let err = register_forge_push_cap(
            &sessions,
            &ctx("http://127.0.0.1:1".into(), "t_acme"),
            "t_evil/app",
            "http://forge.mesh/t_evil/app.git",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, CodeErrorCode::Forbidden);
    }
}
