use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct RepoRiskGateRun {
    pub run_id: Uuid,
    pub repo_url: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub default_branch: Option<String>,
    pub agent_id: Uuid,
    pub status: String,
    pub risk_level: String,
    pub tree_truncated: bool,
    pub files_seen: i32,
    pub ledger_hash: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct RepoRiskGateEvent {
    pub event_id: Uuid,
    pub run_id: Uuid,
    pub agent_id: Uuid,
    pub sequence_no: i32,
    pub event_type: String,
    pub target: Option<String>,
    pub policy_result: Option<String>,
    pub message: String,
    pub metadata: Value,
    pub event_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct RepoRiskGateFinding {
    pub finding_id: Uuid,
    pub run_id: Uuid,
    pub path: String,
    pub matched_rule: String,
    pub policy_result: String,
    pub risk_level: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct RepoRiskGateDecision {
    pub decision_id: Uuid,
    pub run_id: Uuid,
    pub decision: String,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRunRequest {
    pub repo_url: String,
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub decision: String, // APPROVED, ESCALATED, BLOCKED
    pub note: Option<String>,
}

// GitHub API Structs
#[derive(Debug, Deserialize)]
pub struct GitHubRepoResponse {
    pub default_branch: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubTreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String, // "blob" or "tree"
}

#[derive(Debug, Deserialize)]
pub struct GitHubTreeResponse {
    pub tree: Vec<GitHubTreeEntry>,
    pub truncated: bool,
}
