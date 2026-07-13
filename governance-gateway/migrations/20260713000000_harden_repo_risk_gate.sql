-- Migration: Harden Repo Risk Gate Schema

-- Add fields to repo_risk_gate_runs
ALTER TABLE repo_risk_gate_runs
    ADD COLUMN workspace_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN commit_sha TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN tree_hash TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN policy_version TEXT NOT NULL DEFAULT 'v1',
    ADD COLUMN correlation_id TEXT,
    ADD COLUMN pgl_evidence_id TEXT;

-- Remove default constraints for newly inserted rows moving forward (optional, but good practice if we want inserts to fail if missing)
ALTER TABLE repo_risk_gate_runs
    ALTER COLUMN workspace_id DROP DEFAULT,
    ALTER COLUMN commit_sha DROP DEFAULT,
    ALTER COLUMN tree_hash DROP DEFAULT,
    ALTER COLUMN policy_version DROP DEFAULT;

-- Add workspace_id to events
ALTER TABLE repo_risk_gate_events
    ADD COLUMN workspace_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE repo_risk_gate_events ALTER COLUMN workspace_id DROP DEFAULT;

-- Add workspace_id to findings
ALTER TABLE repo_risk_gate_findings
    ADD COLUMN workspace_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
ALTER TABLE repo_risk_gate_findings ALTER COLUMN workspace_id DROP DEFAULT;

-- Add workspace_id and cappo_auth_id to decisions
ALTER TABLE repo_risk_gate_decisions
    ADD COLUMN workspace_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    ADD COLUMN cappo_auth_id TEXT;
ALTER TABLE repo_risk_gate_decisions ALTER COLUMN workspace_id DROP DEFAULT;
