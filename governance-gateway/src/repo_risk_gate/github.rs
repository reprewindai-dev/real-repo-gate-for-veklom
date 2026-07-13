use crate::repo_risk_gate::models::{GitHubRepoResponse, GitHubTreeResponse, GitHubBranchResponse};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, AUTHORIZATION};
use anyhow::{Result, Context};

pub struct GitHubClient {
    client: reqwest::Client,
    token: Option<String>,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("veklom-governance-gateway"));
        if let Some(ref t) = self.token {
            if let Ok(val) = HeaderValue::from_str(&format!("token {}", t)) {
                headers.insert(AUTHORIZATION, val);
            }
        }
        headers
    }

    pub async fn fetch_repo_metadata(&self, owner: &str, repo: &str) -> Result<GitHubRepoResponse> {
        let url = format!("https://api.github.com/repos/{}/{}", owner, repo);
        let resp = self.client.get(&url)
            .headers(self.headers())
            .send()
            .await
            .context("Failed to send request to GitHub repository metadata API")?;
        
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("GitHub API returned error: {}", resp.status()));
        }

        let meta = resp.json::<GitHubRepoResponse>().await
            .context("Failed to parse GitHub repository metadata response")?;
        Ok(meta)
    }

    pub async fn fetch_branch_commit(&self, owner: &str, repo: &str, branch: &str) -> Result<GitHubBranchResponse> {
        let url = format!("https://api.github.com/repos/{}/{}/branches/{}", owner, repo, branch);
        let resp = self.client.get(&url)
            .headers(self.headers())
            .send()
            .await
            .context("Failed to send request to GitHub Branch API")?;
        
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("GitHub Branch API returned error: {}", resp.status()));
        }

        let data = resp.json::<GitHubBranchResponse>().await
            .context("Failed to parse GitHub Branch response")?;
        Ok(data)
    }

    pub async fn fetch_git_tree(&self, owner: &str, repo: &str, branch: &str) -> Result<GitHubTreeResponse> {
        let url = format!("https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1", owner, repo, branch);
        let resp = self.client.get(&url)
            .headers(self.headers())
            .send()
            .await
            .context("Failed to send request to GitHub Git Trees API")?;
        
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("GitHub Git Trees API returned error: {}", resp.status()));
        }

        let tree = resp.json::<GitHubTreeResponse>().await
            .context("Failed to parse GitHub Git Trees response")?;
        Ok(tree)
    }
}
