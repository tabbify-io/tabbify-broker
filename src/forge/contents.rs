//! `ForgeClient` contents methods — `get_file` / `put_file`.
//! Defined here to keep `client.rs` under the 500-line crate-style limit.
//! Compiled as a sibling module (`mod contents` in `forge/mod.rs`).

use super::client::ForgeClient;

/// Decoded file returned by [`ForgeClient::get_file`].
pub struct ForgeFile {
    /// Decoded UTF-8 file content.
    pub content: String,
    /// Git blob SHA — pass back to [`ForgeClient::put_file`] to avoid conflicts.
    pub sha: String,
}

/// Gitea `GET /repos/.../contents/...` response body.
#[derive(serde::Deserialize)]
struct GiteaContent {
    content: String,
    encoding: String,
    sha: String,
}

/// Gitea `PUT /repos/.../contents/...` response body.
#[derive(serde::Deserialize)]
struct GiteaPutResp {
    content: GiteaPutContent,
}

#[derive(serde::Deserialize)]
struct GiteaPutContent {
    sha: String,
}

impl ForgeClient {
    /// GET `/repos/{org}/{repo}/contents/{path}` — read a file from Forgejo.
    /// Returns `None` when the file doesn't exist (404); bails on other errors.
    /// `git_ref` sets `?ref=<branch/tag/sha>`; omit to use the repo default.
    pub async fn get_file(
        &self,
        org: &str,
        repo: &str,
        path: &str,
        git_ref: Option<&str>,
    ) -> anyhow::Result<Option<ForgeFile>> {
        use base64::Engine as _;
        let mut req = self
            .http
            .get(self.api(&format!("/repos/{org}/{repo}/contents/{path}")))
            .header("Authorization", format!("token {}", self.admin_token));
        if let Some(r) = git_ref {
            req = req.query(&[("ref", r)]);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            anyhow::bail!("forge get_file {org}/{repo}: {}", status);
        }
        let body: GiteaContent = resp.json().await?;
        anyhow::ensure!(
            body.encoding == "base64",
            "forge get_file: unexpected encoding {}",
            body.encoding
        );
        // Gitea may insert newlines every 60 chars — strip all whitespace before decode.
        let raw: String = body.content.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD.decode(&raw)?;
        let content = String::from_utf8(bytes)?;
        Ok(Some(ForgeFile { content, sha: body.sha }))
    }

    /// PUT `/repos/{org}/{repo}/contents/{path}` — create or update a file.
    /// `sha` must be `Some(blob_sha)` for updates and `None` for new files.
    /// Returns the new blob SHA from Forgejo's response.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_file(
        &self,
        org: &str,
        repo: &str,
        path: &str,
        message: &str,
        content: &str,
        branch: &str,
        sha: Option<&str>,
    ) -> anyhow::Result<String> {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
        let mut body = serde_json::json!({
            "message": message,
            "content": encoded,
            "branch": branch,
        });
        if let Some(s) = sha {
            body["sha"] = serde_json::Value::String(s.to_owned());
        }
        let resp = self
            .http
            .put(self.api(&format!("/repos/{org}/{repo}/contents/{path}")))
            .header("Authorization", format!("token {}", self.admin_token))
            .json(&body)
            .send()
            .await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "forge put_file {org}/{repo}: {}",
            resp.status()
        );
        let put_resp: GiteaPutResp = resp.json().await?;
        Ok(put_resp.content.sha)
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

    #[tokio::test]
    async fn get_file_decodes_base64() {
        use base64::Engine as _;
        let srv = MockServer::start().await;
        let raw = base64::engine::general_purpose::STANDARD.encode(b"[app]\nname=\"x\"\n");
        // Gitea inserts a newline after the base64 block — strip it during decode.
        let with_newline = format!("{raw}\n");
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/t_acme/app/contents/tabbify.toml"))
            .and(header("authorization", "token admintok"))
            .and(wiremock::matchers::query_param("ref", "main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": with_newline,
                "encoding": "base64",
                "sha": "s1"
            })))
            .mount(&srv)
            .await;
        let file = client(srv.uri())
            .get_file("t_acme", "app", "tabbify.toml", Some("main"))
            .await
            .unwrap()
            .expect("file must be Some when status is 200");
        assert_eq!(file.content, "[app]\nname=\"x\"\n");
        assert_eq!(file.sha, "s1");
    }

    #[tokio::test]
    async fn get_file_missing_is_none() {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/t_acme/app/contents/tabbify.toml"))
            .and(header("authorization", "token admintok"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "message": "Not Found"
            })))
            .mount(&srv)
            .await;
        let result = client(srv.uri())
            .get_file("t_acme", "app", "tabbify.toml", None)
            .await
            .unwrap();
        assert!(result.is_none(), "404 from Forgejo must map to Ok(None)");
    }

    #[tokio::test]
    async fn put_file_sends_base64_and_returns_sha() {
        use base64::Engine as _;
        let srv = MockServer::start().await;
        let expected_content =
            base64::engine::general_purpose::STANDARD.encode(b"[app]\nname=\"y\"\n");
        Mock::given(method("PUT"))
            .and(path("/api/v1/repos/t_acme/app/contents/tabbify.toml"))
            .and(header("authorization", "token admintok"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "message": "update tabbify.toml",
                "content": expected_content,
                "branch": "main",
                "sha": "s1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": {"sha": "s2"}
            })))
            .mount(&srv)
            .await;
        let new_sha = client(srv.uri())
            .put_file(
                "t_acme",
                "app",
                "tabbify.toml",
                "update tabbify.toml",
                "[app]\nname=\"y\"\n",
                "main",
                Some("s1"),
            )
            .await
            .unwrap();
        assert_eq!(new_sha, "s2");
    }

    #[tokio::test]
    async fn put_file_sha_none_omits_sha_key() {
        use base64::Engine as _;
        let srv = MockServer::start().await;
        let expected_content =
            base64::engine::general_purpose::STANDARD.encode(b"[app]\nname=\"new\"\n");
        // body_json does exact JSON equality — if sha were present in the request,
        // this mock would not fire (unmatched → error), proving sha is omitted when None.
        Mock::given(method("PUT"))
            .and(path("/api/v1/repos/t_acme/app/contents/tabbify.toml"))
            .and(header("authorization", "token admintok"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "message": "create tabbify.toml",
                "content": expected_content,
                "branch": "main"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "content": {"sha": "s3"}
            })))
            .mount(&srv)
            .await;
        let new_sha = client(srv.uri())
            .put_file(
                "t_acme",
                "app",
                "tabbify.toml",
                "create tabbify.toml",
                "[app]\nname=\"new\"\n",
                "main",
                None,
            )
            .await
            .unwrap();
        assert_eq!(new_sha, "s3");
    }
}
