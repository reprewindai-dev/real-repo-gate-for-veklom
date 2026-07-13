use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct CappoAuthRequest {
    pub run_id: String,
    pub decision: String,
    pub evidence_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CappoAuthResponse {
    pub cappo_auth_id: String,
    pub status: String, // e.g. "AUTHORIZED", "DENIED"
}

pub struct CappoClient {
    client: reqwest::Client,
    cappo_url: String,
    signing_key: String,
}

impl CappoClient {
    pub fn new(cappo_url: String, signing_key: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            cappo_url,
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

    pub async fn authorize(&self, req: CappoAuthRequest) -> Result<CappoAuthResponse> {
        let url = format!("{}/api/v1/cappo/authorize", self.cappo_url.trim_end_matches('/'));
        let resp = self.client.post(&url)
            .headers(self.headers())
            .json(&req)
            .send()
            .await
            .context("Failed to send request to CAPPO API")?;
        
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("CAPPO API returned error: {}", resp.status()));
        }

        let data = resp.json::<CappoAuthResponse>().await
            .context("Failed to parse CAPPO API response")?;
        
        if data.status != "AUTHORIZED" {
            return Err(anyhow::anyhow!("CAPPO authorization denied: status {}", data.status));
        }

        Ok(data)
    }
}
