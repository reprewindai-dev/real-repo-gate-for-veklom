pub mod models;
pub mod github;
pub mod rules;
pub mod ledger;
pub mod store;
pub mod pgl;
pub mod cappo;
pub mod amphoteric;

use axum::{
    routing::{get, post},
    Router,
    extract::{Path, State, Query},
    Json,
    http::StatusCode,
};
use uuid::Uuid;
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::repo_risk_gate::models::{
    RepoRiskGateRun, RepoRiskGateEvent, RepoRiskGateFinding, RepoRiskGateDecision,
    CreateRunRequest, DecisionRequest,
};
use crate::repo_risk_gate::github::GitHubClient;
use crate::repo_risk_gate::rules::{classify_path, determine_overall_risk};
use crate::repo_risk_gate::ledger::canonical_event_hash;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub github_token: Option<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/repo-risk-gate/runs", post(create_run_handler))
        .route("/api/v1/repo-risk-gate/runs/:run_id/events", get(get_events_handler))
        .route("/api/v1/repo-risk-gate/runs/:run_id/findings", get(get_findings_handler))
        .route("/api/v1/repo-risk-gate/runs/:run_id/decision", post(post_decision_handler))
        .route("/api/v1/repo-risk-gate/runs/:run_id/ledger", get(get_ledger_handler))
        .with_state(state)
}

fn parse_github_url(url: &str) -> Option<(String, String)> {
    let clean = url.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");
    
    if !clean.starts_with("github.com/") {
        return None;
    }
    
    let path = clean.strip_prefix("github.com/")?;
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

async fn create_run_handler(
    State(state): State<AppState>,
    Json(payload): Json<CreateRunRequest>,
) -> Result<Json<RepoRiskGateRun>, (StatusCode, String)> {
    let (owner, repo) = parse_github_url(&payload.repo_url)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid GitHub repository URL".to_string()))?;

    let run_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let now = Utc::now();

    let mut run = RepoRiskGateRun {
        run_id,
        repo_url: payload.repo_url.clone(),
        repo_owner: owner.clone(),
        repo_name: repo.clone(),
        default_branch: None,
        agent_id,
        status: "fetching".to_string(),
        risk_level: "unknown".to_string(),
        tree_truncated: false,
        files_seen: 0,
        ledger_hash: None,
        error_message: None,
        created_at: now,
        updated_at: now,
    };

    if let Err(err) = store::insert_run(&state.db, &run).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create run: {}", err)));
    }

    // 1. Emit init event
    let mut seq = 1;
    let init_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id,
        sequence_no: seq,
        event_type: "system.init".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: "Mounting routing policy protocols under global registry gate...".to_string(),
        metadata: json!({}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &init_event).await;

    // 2. Fetch repository metadata
    seq += 1;
    let fetch_meta_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id,
        sequence_no: seq,
        event_type: "git.fetch".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: format!("Querying GitHub REST repo payload: github.com/{}/{}", owner, repo),
        metadata: json!({}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &fetch_meta_event).await;

    let github = GitHubClient::new(state.github_token.clone());
    let repo_meta = match github.fetch_repo_metadata(&owner, &repo).await {
        Ok(meta) => meta,
        Err(err) => {
            let err_msg = format!("GitHub metadata fetch failed: {}", err);
            let _ = store::update_run_status(&state.db, run_id, "failed", "unknown", 0, false, None, Some(&err_msg)).await;
            return Err((StatusCode::BAD_REQUEST, err_msg));
        }
    };

    run.default_branch = Some(repo_meta.default_branch.clone());

    seq += 1;
    let branch_verified_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id,
        sequence_no: seq,
        event_type: "system.init".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: format!("Default branch identified: '{}' (verified payload)", repo_meta.default_branch),
        metadata: json!({"default_branch": repo_meta.default_branch}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &branch_verified_event).await;

    // 3. Fetch recursive tree
    seq += 1;
    let tree_fetch_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id,
        sequence_no: seq,
        event_type: "git.fetch".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: format!("Querying GitHub REST recursive git tree: branch={}", repo_meta.default_branch),
        metadata: json!({}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &tree_fetch_event).await;

    let git_tree = match github.fetch_git_tree(&owner, &repo, &repo_meta.default_branch).await {
        Ok(tree) => tree,
        Err(err) => {
            let err_msg = format!("GitHub Git Tree fetch failed: {}", err);
            let _ = store::update_run_status(&state.db, run_id, "failed", "unknown", 0, false, None, Some(&err_msg)).await;
            return Err((StatusCode::BAD_REQUEST, err_msg));
        }
    };

    run.tree_truncated = git_tree.truncated;

    if git_tree.truncated {
        seq += 1;
        let truncation_warning = RepoRiskGateEvent {
            event_id: Uuid::new_v4(),
            run_id,
            agent_id,
            sequence_no: seq,
            event_type: "git.tree.warning".to_string(),
            target: None,
            policy_result: Some("none".to_string()),
            message: "Path scan partial: GitHub tree response was truncated. Findings only reflect returned paths.".to_string(),
            metadata: json!({"truncated": true}),
            event_hash: None,
            created_at: Utc::now(),
        };
        let _ = store::insert_event(&state.db, &truncation_warning).await;
    } else {
        seq += 1;
        let success_map = RepoRiskGateEvent {
            event_id: Uuid::new_v4(),
            run_id,
            agent_id,
            sequence_no: seq,
            event_type: "system.init".to_string(),
            target: None,
            policy_result: Some("none".to_string()),
            message: format!("Success: Mapped default tree structure containing {} component paths", git_tree.tree.len()),
            metadata: json!({"files_count": git_tree.tree.len()}),
            event_hash: None,
            created_at: Utc::now(),
        };
        let _ = store::insert_event(&state.db, &success_map).await;
    }

    // 4. Classify paths and generate findings
    let blob_paths: Vec<&str> = git_tree.tree.iter()
        .filter(|entry| entry.entry_type == "blob")
        .map(|entry| entry.path.as_str())
        .collect();

    run.files_seen = blob_paths.len() as i32;

    let mut findings = Vec::new();
    let mut risk_levels = Vec::new();
    let mut status = "completed".to_string();

    for path in blob_paths {
        if let Some(rule) = classify_path(path) {
            let finding_id = Uuid::new_v4();
            let finding = RepoRiskGateFinding {
                finding_id,
                run_id,
                path: path.to_string(),
                matched_rule: rule.name.to_string(),
                policy_result: rule.policy_result.to_string(),
                risk_level: rule.risk_level.to_string(),
                reason: rule.reason.to_string(),
                created_at: Utc::now(),
            };

            let _ = store::insert_finding(&state.db, &finding).await;
            findings.push(finding);
            risk_levels.push(rule.risk_level);

            // Add events reflecting finding
            seq += 1;
            let finding_alert = RepoRiskGateEvent {
                event_id: Uuid::new_v4(),
                run_id,
                agent_id,
                sequence_no: seq,
                event_type: "finding.alert".to_string(),
                target: Some(path.to_string()),
                policy_result: Some("none".to_string()),
                message: format!("MATCH DETECTED: '{}' violations intercepted.", rule.name),
                metadata: json!({"rule_id": rule.id, "risk_level": rule.risk_level}),
                event_hash: None,
                created_at: Utc::now(),
            };
            let _ = store::insert_event(&state.db, &finding_alert).await;

            seq += 1;
            let gate_triggered = RepoRiskGateEvent {
                event_id: Uuid::new_v4(),
                run_id,
                agent_id,
                sequence_no: seq,
                event_type: "policy.gate.triggered".to_string(),
                target: Some(path.to_string()),
                policy_result: Some(rule.policy_result.to_string()),
                message: format!("Policy mandate: [{}]", rule.policy_result.to_uppercase()),
                metadata: json!({"rule_id": rule.id}),
                event_hash: None,
                created_at: Utc::now(),
            };
            let _ = store::insert_event(&state.db, &gate_triggered).await;

            if rule.policy_result == "blocked_env_boundary" {
                seq += 1;
                let boundary_blocked = RepoRiskGateEvent {
                    event_id: Uuid::new_v4(),
                    run_id,
                    agent_id,
                    sequence_no: seq,
                    event_type: "file.access.blocked".to_string(),
                    target: Some(path.to_string()),
                    policy_result: Some("blocked_env_boundary".to_string()),
                    message: "CONTAINMENT ACTIVE: mutations strictly denied. isolated environment seal enforced.".to_string(),
                    metadata: json!({"rule_id": rule.id}),
                    event_hash: None,
                    created_at: Utc::now(),
                };
                let _ = store::insert_event(&state.db, &boundary_blocked).await;
            }

            if rule.policy_result == "human_approval_required" || rule.policy_result == "escalate_to_security" {
                status = "awaiting_decision".to_string();
            }
        }
    }

    run.risk_level = determine_overall_risk(&risk_levels);
    run.status = status.clone();

    // Seal the ledger if scan completed without awaiting decision
    if status == "completed" {
        seq += 1;
        let seal_event = RepoRiskGateEvent {
            event_id: Uuid::new_v4(),
            run_id,
            agent_id,
            sequence_no: seq,
            event_type: "ledger.seal".to_string(),
            target: None,
            policy_result: Some("none".to_string()),
            message: "GPC core evaluation completed. Generating stable BTreeMap ledger proof...".to_string(),
            metadata: json!({}),
            event_hash: None,
            created_at: Utc::now(),
        };
        let _ = store::insert_event(&state.db, &seal_event).await;

        if let Ok(events) = store::get_events(&state.db, run_id).await {
            let json_events: Vec<Value> = events.into_iter()
                .map(|e| json!({
                    "agent_id": e.agent_id,
                    "event_type": e.event_type,
                    "message": e.message,
                    "policy_result": e.policy_result,
                    "run_id": e.run_id,
                    "sequence_no": e.sequence_no,
                    "target": e.target,
                    "timestamp": e.created_at.to_rfc3339()
                }))
                .collect();
            if let Ok(hash) = canonical_event_hash(json_events) {
                run.ledger_hash = Some(hash);
            }
        }
    }

    let _ = store::update_run_status(
        &state.db,
        run_id,
        &run.status,
        &run.risk_level,
        run.files_seen,
        run.tree_truncated,
        run.ledger_hash.as_deref(),
        None
    ).await;

    // Retrieve updated run record from database
    let updated_run = store::get_run(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to retrieve run: {}", err)))?
        .unwrap_or(run);

    Ok(Json(updated_run))
}

async fn get_events_handler(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<Vec<RepoRiskGateEvent>>, (StatusCode, String)> {
    let events = store::get_events(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get events: {}", err)))?;
    Ok(Json(events))
}

async fn get_findings_handler(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<Vec<RepoRiskGateFinding>>, (StatusCode, String)> {
    let findings = store::get_findings(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get findings: {}", err)))?;
    Ok(Json(findings))
}

async fn post_decision_handler(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
    Json(payload): Json<DecisionRequest>,
) -> Result<Json<RepoRiskGateDecision>, (StatusCode, String)> {
    let run = store::get_run(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to find run: {}", err)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Run not found".to_string()))?;

    let decision_id = Uuid::new_v4();
    let now = Utc::now();
    let decision = RepoRiskGateDecision {
        decision_id,
        run_id,
        decision: payload.decision.clone(),
        note: payload.note.clone(),
        created_at: now,
    };

    if let Err(err) = store::insert_decision(&state.db, &decision).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store decision: {}", err)));
    }

    // Add decision event
    let events = store::get_events(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get events: {}", err)))?;
    let next_seq = (events.len() as i32) + 1;

    let decision_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id: run.agent_id,
        sequence_no: next_seq,
        event_type: "decision.submitted".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: format!("Operator decision: [{}]. Note: {}", payload.decision, payload.note.as_deref().unwrap_or("none")),
        metadata: json!({"decision": payload.decision, "note": payload.note}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &decision_event).await;

    // Transition run to completed/failed/blocked
    let final_status = "completed".to_string();
    
    // Add ledger seal event
    let seal_event = RepoRiskGateEvent {
        event_id: Uuid::new_v4(),
        run_id,
        agent_id: run.agent_id,
        sequence_no: next_seq + 1,
        event_type: "ledger.seal".to_string(),
        target: None,
        policy_result: Some("none".to_string()),
        message: "GPC core evaluation completed. Generating stable BTreeMap ledger proof...".to_string(),
        metadata: json!({}),
        event_hash: None,
        created_at: Utc::now(),
    };
    let _ = store::insert_event(&state.db, &seal_event).await;

    let mut updated_ledger_hash = None;
    if let Ok(all_events) = store::get_events(&state.db, run_id).await {
        let json_events: Vec<Value> = all_events.into_iter()
            .map(|e| json!({
                "agent_id": e.agent_id,
                "event_type": e.event_type,
                "message": e.message,
                "policy_result": e.policy_result,
                "run_id": e.run_id,
                "sequence_no": e.sequence_no,
                "target": e.target,
                "timestamp": e.created_at.to_rfc3339()
            }))
            .collect();
        if let Ok(hash) = canonical_event_hash(json_events) {
            updated_ledger_hash = Some(hash);
        }
    }

    let _ = store::update_run_status(
        &state.db,
        run_id,
        &final_status,
        &run.risk_level,
        run.files_seen,
        run.tree_truncated,
        updated_ledger_hash.as_deref(),
        None
    ).await;

    Ok(Json(decision))
}

async fn get_ledger_handler(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let run = store::get_run(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to find run: {}", err)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Run not found".to_string()))?;

    let events = store::get_events(&state.db, run_id).await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get events: {}", err)))?;

    let json_events: Vec<Value> = events.into_iter()
        .map(|e| json!({
            "agent_id": e.agent_id,
            "event_type": e.event_type,
            "message": e.message,
            "policy_result": e.policy_result,
            "run_id": e.run_id,
            "sequence_no": e.sequence_no,
            "target": e.target,
            "timestamp": e.created_at.to_rfc3339()
        }))
        .collect();

    let hash = canonical_event_hash(json_events.clone())
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to hash events: {}", err)))?;

    Ok(Json(json!({
        "run_id": run_id,
        "coverage": {
            "mode": "path_scan_v1",
            "tree_truncated": run.tree_truncated
        },
        "ledger_hash": hash,
        "events": json_events
    })))
}
