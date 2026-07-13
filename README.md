# Veklom Sovereign Governance Gateway (RepoGate)

`reprewindai-dev/real-repo-gate-for-veklom` is the canonical RepoGate implementation for Veklom.
It is an independent capability and authority domain that evaluates repositories and enforces policies.

## Architecture

1. **RepoGate** owns repository inspection, findings, risk classification, policy evaluation, run state, and RepoGate evidence.
2. **PGL** owns canonical evidence sealing and verification.
3. **CAPPO** owns authorization of consequential follow-on actions.
4. **GPC** compiles remediation and deployment plans.
5. **Interlink cAPI** publishes and coordinates RepoGate capabilities.
6. **Amphoteric Runtime** exposes equivalent REST, MCP, SDK, and browser-native representations.

## Capabilities

The Amphoteric interface (`/mcp`) provides the following capabilities:
* `repogate.run.create`
* `repogate.run.read`
* `repogate.events.subscribe`
* `repogate.findings.read`
* `repogate.evidence.verify`
* `repogate.decision.submit`
* `repogate.remediation.request`
* `repogate.execution.authorize`

## Hardening Standards

This implementation strictly adheres to the following:
* Strict origin allowlists (no permissive CORS).
* Mandatory workload identity (JWT) for authentication and participant isolation.
* Canonical event-hash chaining `H_n = SHA256(H_{n-1} || canonical_json(event_n))`.
* Cryptographic evidence sealing through PGL.
* Consequential actions require explicit CAPPO authorization.
* Database runs are inextricably bound to a `workspace_id`, `commit_sha`, and `tree_hash`.
