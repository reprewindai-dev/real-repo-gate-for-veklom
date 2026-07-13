-- Migration: Repo Risk Gate v1 Schema Setup

CREATE TABLE IF NOT EXISTS repo_risk_gate_runs (
    run_id UUID PRIMARY KEY,
    repo_url TEXT NOT NULL,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    default_branch TEXT,
    agent_id UUID NOT NULL,
    status TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'unknown',
    tree_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    files_seen INTEGER NOT NULL DEFAULT 0,
    ledger_hash TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS repo_risk_gate_events (
    event_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES repo_risk_gate_runs(run_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,
    sequence_no INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT,
    policy_result TEXT,
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(run_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS repo_risk_gate_findings (
    finding_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES repo_risk_gate_runs(run_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    matched_rule TEXT NOT NULL,
    policy_result TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS repo_risk_gate_decisions (
    decision_id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES repo_risk_gate_runs(run_id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
