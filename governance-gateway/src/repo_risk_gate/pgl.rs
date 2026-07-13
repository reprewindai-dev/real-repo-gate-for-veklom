use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct PglSealRequest {
    pub run_id: String,
    pub tree_hash: String,
    pub commit_sha: String,
    pub policy_version: String,
    pub findings_hash: String,
    pub canonical_ledger_hash: String,
}

#[derive(Deserialize)]
pub struct PglSealResponse {
    pub pgl_evidence_id: String,
}

pub struct PglClient {
    client: reqwest::Client,
    pgl_url: String,
    signing_key: String,
}

impl PglClient {
    pub fn new(pgl_url: String, signing_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            pgl_url,
            signing_key,
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", self.signing_key)) {
            headers.insert(AUTHORIZATION, val);
        }
        headers
    }

    pub async fn seal_evidence(&self, req: PglSealRequest) -> Result<PglSealResponse> {
        let url = format!("{}/api/v1/pgl/seal", self.pgl_url.trim_end_matches('/'));
        let resp = self.client.post(&url)
            .headers(self.headers())
            .json(&req)
            .send()
            .await
            .context("Failed to send request to PGL API")?;
        
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("PGL API returned error: {}", resp.status()));
        }

        let data = resp.json::<PglSealResponse>().await
            .context("Failed to parse PGL API response")?;
        Ok(data)
    }
}
