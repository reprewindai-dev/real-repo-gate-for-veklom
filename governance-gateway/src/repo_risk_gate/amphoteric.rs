use axum::{Json, response::IntoResponse};
use serde_json::{json, Value};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

pub async fn handle_mcp_request(Json(payload): Json<McpRequest>) -> impl IntoResponse {
    let result = match payload.method.as_str() {
        "repogate.run.create" => json!({"status": "mock_success", "action": "run_created"}),
        "repogate.run.read" => json!({"status": "mock_success", "action": "run_read"}),
        "repogate.events.subscribe" => json!({"status": "mock_success", "action": "events_subscribed"}),
        "repogate.findings.read" => json!({"status": "mock_success", "action": "findings_read"}),
        "repogate.evidence.verify" => json!({"status": "mock_success", "action": "evidence_verified"}),
        "repogate.decision.submit" => json!({"status": "mock_success", "action": "decision_submitted"}),
        "repogate.remediation.request" => json!({"status": "mock_success", "action": "remediation_requested"}),
        "repogate.execution.authorize" => json!({"status": "mock_success", "action": "execution_authorized"}),
        _ => json!({"error": "Method not found", "code": -32601}),
    };

    Json(json!({
        "jsonrpc": "2.0",
        "id": payload.id,
        "result": result
    }))
}
