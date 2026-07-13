use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub backend_url: String,
    pub authority: String,
    pub pgl_enabled: bool,
    pub audit_log_enabled: bool,
    pub gateway_port: u16,
    pub log_level: String,
    pub database_url: String,
    pub github_token: Option<String>,
    pub pgl_url: String,
    pub cappo_url: String,
    pub signing_key: String,
    pub policy_version: String,
    pub allowed_origins: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            backend_url: env::var("BACKEND_URL").unwrap_or_else(|_| "http://localhost:8000".to_string()),
            authority: env::var("AUTHORITY").unwrap_or_else(|_| "Veklom Sovereign".to_string()),
            pgl_enabled: env::var("PGL_ENABLED")
                .map(|s| s == "true")
                .unwrap_or(true),
            audit_log_enabled: env::var("AUDIT_LOG_ENABLED")
                .map(|s| s == "true")
                .unwrap_or(true),
            gateway_port: env::var("GATEWAY_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3000),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            github_token: env::var("GITHUB_TOKEN").ok(),
            pgl_url: env::var("PGL_URL").expect("PGL_URL must be set"),
            cappo_url: env::var("CAPPO_URL").expect("CAPPO_URL must be set"),
            signing_key: env::var("SIGNING_KEY").expect("SIGNING_KEY must be set"),
            policy_version: env::var("POLICY_VERSION").expect("POLICY_VERSION must be set"),
            allowed_origins: env::var("ALLOWED_ORIGINS").expect("ALLOWED_ORIGINS must be set"),
        }
    }
}
