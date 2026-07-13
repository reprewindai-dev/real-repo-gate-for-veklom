use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: &'static str,
    pub name: &'static str,
    pub patterns: &'static [&'static str],
    pub policy_result: &'static str,
    pub risk_level: &'static str,
    pub reason: &'static str,
}

pub static RULES: &[PolicyRule] = &[
    PolicyRule {
        id: "rule_env_secrets",
        name: "Secrets Registry Leak Policy",
        patterns: &[".env", "secrets", "credentials", ".key", ".pem"],
        policy_result: "read_blocked",
        risk_level: "HIGH",
        reason: "Matches sensitive file patterns that hold unencrypted cryptographic credentials or local credentials keys.",
    },
    PolicyRule {
        id: "rule_auth_routes",
        name: "Authentication Module Safety Policy",
        patterns: &["auth", "login", "jwt", "session", "oauth", "config.rs"],
        policy_result: "human_approval_required",
        risk_level: "CRITICAL",
        reason: "Accessing core authorization or user session routines requires explicit Operator signature.",
    },
    PolicyRule {
        id: "rule_billing_stripe",
        name: "Financial Ledger Transaction Policy",
        patterns: &["billing", "stripe", "payment", "invoice", "subscription", "webhook"],
        policy_result: "human_approval_required",
        risk_level: "HIGH",
        reason: "Agent requested read/write permissions on stripe ledger billing pipelines.",
    },
    PolicyRule {
        id: "rule_migrations_db",
        name: "Multi-Tenant RBAC Boundary Policy",
        patterns: &["migrations", "tenant", "workspace", "rbac", ".sql"],
        policy_result: "escalate_to_security",
        risk_level: "HIGH",
        reason: "Database mutations or permission alterations detected. Requires senior security escalation.",
    },
    PolicyRule {
        id: "rule_deployments",
        name: "Infrastructure Boundary Guard",
        patterns: &["deploy", "k8s", "terraform", "docker", "production", "cluster"],
        policy_result: "blocked_env_boundary",
        risk_level: "CRITICAL",
        reason: "Direct orchestrator mutations on production-level cluster elements are strictly forbidden.",
    },
    PolicyRule {
        id: "rule_ci_cd",
        name: "Continuous Integration Review Policy",
        patterns: &["github/workflows", "ci", "cd", "yaml", "yml"],
        policy_result: "review_required",
        risk_level: "MEDIUM",
        reason: "CI/CD pipeline file alterations found. General review is required.",
    }
];

pub fn classify_path(path: &str) -> Option<&'static PolicyRule> {
    let lower_path = path.to_lowercase();
    for rule in RULES {
        for pattern in rule.patterns {
            if lower_path.contains(pattern) {
                return Some(rule);
            }
        }
    }
    None
}

pub fn determine_overall_risk(risk_levels: &[&str]) -> String {
    if risk_levels.is_empty() {
        return "SAFE".to_string();
    }
    let mut max_val = 0;
    let mut top_risk = "SAFE";
    for r in risk_levels {
        let val = match *r {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        };
        if val > max_val {
            max_val = val;
            top_risk = r;
        }
    }
    top_risk.to_string()
}
