//! Thin Forgejo REST client over the forge's MESH ULA. Holds the forge org
//! owner creds (admin token + the per-org owner-user + its password); the agent
//! never sees them. Returns the contract `ForgeRepoInfo`/`ForgePrResp`/
//! `ForgeUrlResp` shapes so the codeservice/MCP layer is type-stable.
//!
//! Forgejo API shapes are pinned against the Forgejo v10 REST docs (`user/token-scope`,
//! `user/api-usage`). The load-bearing call is `ensure_scoped_token`: an ORG
//! cannot own a personal access token — `POST /api/v1/users/{name}/tokens` is
//! user-only and requires BasicAuth+password (not a token header). So the scoped
//! push credential is the per-org OWNER-USER's token, minted via BasicAuth. Live
//! verification against a running Forgejo is infra-gated (see Task 13 script);
//! the request shapes here are asserted by wiremock against the documented API.

use tabbify_workspace_contract::rpc::{ForgePrResp, ForgeRepoInfo, ForgeUrlResp};

/// Forgejo REST client bound to one forge base URL + the org owner creds.
/// `root_url` is the externally shareable base Forgejo bakes into web links
/// (used by `file_url`, which builds the link without a network call).
pub struct ForgeClient {
    base_url: String,
    root_url: String,
    admin_token: String,
    owner_user: String,
    owner_password: String,
    http: reqwest::Client,
}

/// Forgejo's repo JSON (the fields we map to `ForgeRepoInfo`).
#[derive(serde::Deserialize)]
struct ForgejoRepo {
    name: String,
    full_name: String,
    clone_url: String,
    html_url: String,
    default_branch: String,
    private: bool,
}

impl ForgejoRepo {
    fn into_info(self) -> ForgeRepoInfo {
        ForgeRepoInfo {
            name: self.name,
            full_name: self.full_name,
            clone_url: self.clone_url,
            web_url: self.html_url,
            default_branch: self.default_branch,
            private: self.private,
        }
    }
}

/// Forgejo's access-token JSON (`GET`/`POST /users/{u}/tokens`).
#[derive(serde::Deserialize)]
struct ForgejoToken {
    name: String,
    /// Present ONLY on POST (mint); absent on GET (list). Forgejo never returns
    /// the secret again, so a missing/blank token on a FOUND-by-name entry means
    /// "exists but secret unknown" → we must mint a fresh one.
    #[serde(default)]
    sha1: String,
}

impl ForgeClient {
    #[must_use]
    pub fn new(
        base_url: String,
        root_url: String,
        admin_token: String,
        owner_user: String,
        owner_password: String,
    ) -> Self {
        Self {
            base_url,
            root_url,
            admin_token,
            owner_user,
            owner_password,
            http: reqwest::Client::new(),
        }
    }

    fn api(&self, suffix: &str) -> String {
        format!("{}/api/v1{suffix}", self.base_url.trim_end_matches('/'))
    }

    /// Create a repo in `org`. Forgejo: `POST /api/v1/orgs/{org}/repos`.
    pub async fn create_org_repo(
        &self,
        org: &str,
        name: &str,
        private: bool,
        description: Option<&str>,
    ) -> anyhow::Result<ForgeRepoInfo> {
        let resp = self
            .http
            .post(self.api(&format!("/orgs/{org}/repos")))
            .header("Authorization", format!("token {}", self.admin_token))
            .json(&serde_json::json!({
                "name": name,
                "private": private,
                "description": description.unwrap_or(""),
                "auto_init": true,
            }))
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "forge create_org_repo: {}", resp.status());
        let repo: ForgejoRepo = resp.json().await?;
        Ok(repo.into_info())
    }

    /// List repos in `org`. Forgejo: `GET /api/v1/orgs/{org}/repos`.
    pub async fn list_org_repos(&self, org: &str) -> anyhow::Result<Vec<ForgeRepoInfo>> {
        let resp = self
            .http
            .get(self.api(&format!("/orgs/{org}/repos")))
            .header("Authorization", format!("token {}", self.admin_token))
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "forge list_org_repos: {}", resp.status());
        let repos: Vec<ForgejoRepo> = resp.json().await?;
        Ok(repos.into_iter().map(ForgejoRepo::into_info).collect())
    }

    /// Find-or-mint the per-org owner-user's scoped token — the credential the
    /// broker injects on push (D1 custody). Forgejo restricts token minting to
    /// **BasicAuth(owner_user, owner_password)** (NOT a token header), so we mint
    /// as the owner-user. The token is org-scoped because the owner-user is an
    /// owner of exactly this one org. Returns the raw secret (broker holds it;
    /// the agent never sees it). `token_name` namespaces the broker's token so
    /// repeat mints don't accumulate (we drop+re-mint by name when the secret is
    /// not recoverable, since Forgejo only returns the secret at creation time).
    pub async fn ensure_scoped_token(&self, token_name: &str) -> anyhow::Result<String> {
        let u = &self.owner_user;
        // Existing token by this name? Forgejo never re-reveals the secret, so a
        // found entry is useless to us — delete it, then mint fresh.
        let list = self
            .http
            .get(self.api(&format!("/users/{u}/tokens")))
            .basic_auth(u, Some(&self.owner_password))
            .send()
            .await?;
        if list.status().is_success() {
            let existing: Vec<ForgejoToken> = list.json().await.unwrap_or_default();
            if existing.iter().any(|t| t.name == token_name) {
                let _ = self
                    .http
                    .delete(self.api(&format!("/users/{u}/tokens/{token_name}")))
                    .basic_auth(u, Some(&self.owner_password))
                    .send()
                    .await;
            }
        }
        let resp = self
            .http
            .post(self.api(&format!("/users/{u}/tokens")))
            .basic_auth(u, Some(&self.owner_password))
            .json(&serde_json::json!({
                "name": token_name,
                "scopes": ["write:organization", "write:repository"],
            }))
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "forge mint scoped token: {}", resp.status());
        let tok: ForgejoToken = resp.json().await?;
        anyhow::ensure!(!tok.sha1.is_empty(), "forge scoped token response missing sha1");
        Ok(tok.sha1)
    }

    /// Open a PR. Forgejo: `POST /api/v1/repos/{org}/{repo}/pulls`. Returns the
    /// contract `ForgePrResp { number, web_url }`.
    pub async fn open_pr(
        &self,
        org: &str,
        repo: &str,
        title: &str,
        head: &str,
        base: &str,
        body: Option<&str>,
    ) -> anyhow::Result<ForgePrResp> {
        #[derive(serde::Deserialize)]
        struct ForgejoPr {
            number: u32,
            html_url: String,
        }
        let resp = self
            .http
            .post(self.api(&format!("/repos/{org}/{repo}/pulls")))
            .header("Authorization", format!("token {}", self.admin_token))
            .json(&serde_json::json!({
                "title": title,
                "head": head,
                "base": base,
                "body": body.unwrap_or(""),
            }))
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "forge open_pr: {}", resp.status());
        let pr: ForgejoPr = resp.json().await?;
        Ok(ForgePrResp { number: pr.number, web_url: pr.html_url })
    }

    /// The repo's default branch (used when `forge_file_url` omits `ref`).
    pub async fn default_branch(&self, org: &str, repo: &str) -> anyhow::Result<String> {
        let resp = self
            .http
            .get(self.api(&format!("/repos/{org}/{repo}")))
            .header("Authorization", format!("token {}", self.admin_token))
            .send()
            .await?;
        anyhow::ensure!(resp.status().is_success(), "forge get repo: {}", resp.status());
        let repo: ForgejoRepo = resp.json().await?;
        Ok(repo.default_branch)
    }

    /// Build a shareable web link to a file at a ref. Pure string build against
    /// `root_url` (no network) — Forgejo's web path is `/{org}/{repo}/src/{ref}/{path}`.
    #[must_use]
    pub fn file_url(&self, org: &str, repo: &str, git_ref: &str, file_path: &str) -> ForgeUrlResp {
        let base = self.root_url.trim_end_matches('/');
        let path = file_path.trim_start_matches('/');
        ForgeUrlResp { web_url: format!("{base}/{org}/{repo}/src/{git_ref}/{path}") }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(uri: String) -> ForgeClient {
        ForgeClient::new(
            uri,
            "http://forge.mesh".into(),
            "admintok".into(),
            "t_acme-bot".into(),
            "ownerpw".into(),
        )
    }

    fn forgejo_repo_json(name: &str, org: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "full_name": format!("{org}/{name}"),
            "clone_url": format!("http://forge.mesh/{org}/{name}.git"),
            "html_url": format!("http://forge.mesh/{org}/{name}"),
            "default_branch": "main",
            "private": true
        })
    }

    #[tokio::test]
    async fn create_org_repo_maps_to_contract_shape() {
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/orgs/t_acme/repos"))
            .and(header("authorization", "token admintok"))
            .respond_with(ResponseTemplate::new(201).set_body_json(forgejo_repo_json("app", "t_acme")))
            .mount(&srv)
            .await;

        let info = client(srv.uri()).create_org_repo("t_acme", "app", true, Some("demo")).await.unwrap();
        assert_eq!(info.full_name, "t_acme/app");
        assert_eq!(info.default_branch, "main");
        assert!(info.private);
        assert!(info.web_url.ends_with("/t_acme/app"));
        assert!(info.clone_url.ends_with("/t_acme/app.git"));
    }

    #[tokio::test]
    async fn list_org_repos_maps_each_repo() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/orgs/t_acme/repos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                forgejo_repo_json("a", "t_acme"),
                forgejo_repo_json("b", "t_acme"),
            ])))
            .mount(&srv)
            .await;
        let repos = client(srv.uri()).list_org_repos("t_acme").await.unwrap();
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[1].full_name, "t_acme/b");
    }

    #[tokio::test]
    async fn ensure_scoped_token_mints_via_basic_auth_and_returns_secret() {
        let srv = MockServer::start().await;
        // No pre-existing token by name (empty list).
        Mock::given(method("GET"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            // BasicAuth(t_acme-bot:ownerpw) == base64("t_acme-bot:ownerpw")
            .and(header("authorization", "Basic dF9hY21lLWJvdDpvd25lcnB3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&srv)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            .and(header("authorization", "Basic dF9hY21lLWJvdDpvd25lcnB3"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "name": "broker-push",
                "sha1": "scoped_tok_xyz"
            })))
            .mount(&srv)
            .await;
        let tok = client(srv.uri()).ensure_scoped_token("broker-push").await.unwrap();
        assert_eq!(tok, "scoped_tok_xyz");
        assert!(!tok.is_empty(), "scoped token must be non-empty (D1 push credential)");
    }

    #[tokio::test]
    async fn ensure_scoped_token_errors_when_mint_omits_sha1() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&srv)
            .await;
        // A mint response with a blank secret must be a HARD error (never a fake
        // success that strands the broker with an unusable credential).
        Mock::given(method("POST"))
            .and(path("/api/v1/users/t_acme-bot/tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "name": "broker-push", "sha1": ""
            })))
            .mount(&srv)
            .await;
        assert!(client(srv.uri()).ensure_scoped_token("broker-push").await.is_err());
    }

    #[tokio::test]
    async fn open_pr_maps_to_contract_pr_resp() {
        let srv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/repos/t_acme/app/pulls"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 7,
                "html_url": "http://forge.mesh/t_acme/app/pulls/7"
            })))
            .mount(&srv)
            .await;
        let pr = client(srv.uri()).open_pr("t_acme", "app", "T", "feat", "main", Some("b")).await.unwrap();
        assert_eq!(pr.number, 7);
        assert_eq!(pr.web_url, "http://forge.mesh/t_acme/app/pulls/7");
    }

    #[tokio::test]
    async fn default_branch_reads_repo() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/t_acme/app"))
            .respond_with(ResponseTemplate::new(200).set_body_json(forgejo_repo_json("app", "t_acme")))
            .mount(&srv)
            .await;
        assert_eq!(client(srv.uri()).default_branch("t_acme", "app").await.unwrap(), "main");
    }

    #[test]
    fn file_url_builds_shareable_src_link() {
        let c = client("http://unused".into());
        let u = c.file_url("t_acme", "app", "main", "/src/lib.rs");
        assert_eq!(u.web_url, "http://forge.mesh/t_acme/app/src/main/src/lib.rs");
    }
}
