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
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string()),
            github_token: env::var("GITHUB_TOKEN").ok(),
        }
    }
}
