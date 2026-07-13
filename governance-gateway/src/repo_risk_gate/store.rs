use crate::repo_risk_gate::models::{RepoRiskGateRun, RepoRiskGateEvent, RepoRiskGateFinding, RepoRiskGateDecision};
use sqlx::{PgPool, Result};
use uuid::Uuid;

pub async fn insert_run(pool: &PgPool, run: &RepoRiskGateRun) -> Result<()> {
    sqlx::query(
        "INSERT INTO repo_risk_gate_runs (run_id, repo_url, repo_owner, repo_name, default_branch, agent_id, status, risk_level, tree_truncated, files_seen, ledger_hash, error_message, created_at, updated_at, workspace_id, commit_sha, tree_hash, policy_version, correlation_id, pgl_evidence_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)"
    )
    .bind(run.run_id)
    .bind(&run.repo_url)
    .bind(&run.repo_owner)
    .bind(&run.repo_name)
    .bind(&run.default_branch)
    .bind(run.agent_id)
    .bind(&run.status)
    .bind(&run.risk_level)
    .bind(run.tree_truncated)
    .bind(run.files_seen)
    .bind(&run.ledger_hash)
    .bind(&run.error_message)
    .bind(run.created_at)
    .bind(run.updated_at)
    .bind(run.workspace_id)
    .bind(&run.commit_sha)
    .bind(&run.tree_hash)
    .bind(&run.policy_version)
    .bind(&run.correlation_id)
    .bind(&run.pgl_evidence_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn update_run_status(
    pool: &PgPool,
    run_id: Uuid,
    status: &str,
    risk_level: &str,
    files_seen: i32,
    tree_truncated: bool,
    ledger_hash: Option<&str>,
    error_message: Option<&str>
) -> Result<()> {
    sqlx::query(
        "UPDATE repo_risk_gate_runs \
         SET status = $1, risk_level = $2, files_seen = $3, tree_truncated = $4, ledger_hash = $5, error_message = $6, updated_at = now() \
         WHERE run_id = $7"
    )
    .bind(status)
    .bind(risk_level)
    .bind(files_seen)
    .bind(tree_truncated)
    .bind(ledger_hash)
    .bind(error_message)
    .bind(run_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_run(pool: &PgPool, run_id: Uuid) -> Result<Option<RepoRiskGateRun>> {
    let run = sqlx::query_as::<_, RepoRiskGateRun>(
        "SELECT * FROM repo_risk_gate_runs WHERE run_id = $1"
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await?;

    Ok(run)
}

pub async fn insert_event(pool: &PgPool, event: &RepoRiskGateEvent) -> Result<()> {
    sqlx::query(
        "INSERT INTO repo_risk_gate_events (event_id, run_id, agent_id, sequence_no, event_type, target, policy_result, message, metadata, event_hash, created_at, workspace_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
    )
    .bind(event.event_id)
    .bind(event.run_id)
    .bind(event.agent_id)
    .bind(event.sequence_no)
    .bind(&event.event_type)
    .bind(&event.target)
    .bind(&event.policy_result)
    .bind(&event.message)
    .bind(&event.metadata)
    .bind(&event.event_hash)
    .bind(event.created_at)
    .bind(event.workspace_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_events(pool: &PgPool, run_id: Uuid) -> Result<Vec<RepoRiskGateEvent>> {
    let events = sqlx::query_as::<_, RepoRiskGateEvent>(
        "SELECT * FROM repo_risk_gate_events WHERE run_id = $1 ORDER BY sequence_no ASC"
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

pub async fn insert_finding(pool: &PgPool, finding: &RepoRiskGateFinding) -> Result<()> {
    sqlx::query(
        "INSERT INTO repo_risk_gate_findings (finding_id, run_id, path, matched_rule, policy_result, risk_level, reason, created_at, workspace_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(finding.finding_id)
    .bind(finding.run_id)
    .bind(&finding.path)
    .bind(&finding.matched_rule)
    .bind(&finding.policy_result)
    .bind(&finding.risk_level)
    .bind(&finding.reason)
    .bind(finding.created_at)
    .bind(finding.workspace_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_findings(pool: &PgPool, run_id: Uuid) -> Result<Vec<RepoRiskGateFinding>> {
    let findings = sqlx::query_as::<_, RepoRiskGateFinding>(
        "SELECT * FROM repo_risk_gate_findings WHERE run_id = $1 ORDER BY created_at ASC"
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;

    Ok(findings)
}

pub async fn insert_decision(pool: &PgPool, decision: &RepoRiskGateDecision) -> Result<()> {
    sqlx::query(
        "INSERT INTO repo_risk_gate_decisions (decision_id, run_id, decision, note, created_at, workspace_id, cappo_auth_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(decision.decision_id)
    .bind(decision.run_id)
    .bind(&decision.decision)
    .bind(&decision.note)
    .bind(decision.created_at)
    .bind(decision.workspace_id)
    .bind(&decision.cappo_auth_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_decision(pool: &PgPool, run_id: Uuid) -> Result<Option<RepoRiskGateDecision>> {
    let decision = sqlx::query_as::<_, RepoRiskGateDecision>(
        "SELECT * FROM repo_risk_gate_decisions WHERE run_id = $1 LIMIT 1"
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await?;

    Ok(decision)
}
