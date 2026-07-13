use axum::{
    routing::{get, post},
    Router,
    response::IntoResponse,
    Json,
};
use std::net::SocketAddr;
use tower_http::{cors::{CorsLayer, Any}, trace::TraceLayer};
use tower::ServiceBuilder;
use http::{Method, header::{AUTHORIZATION, CONTENT_TYPE}};
use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use sqlx::postgres::PgPoolOptions;

mod config;
mod repo_risk_gate;

use config::Config;
use repo_risk_gate::AppState;

async fn auth_middleware(req: Request, next: Next) -> Result<Response, (axum::http::StatusCode, String)> {
    // Basic participant isolation and workload identity middleware
    let headers = req.headers();
    if let Some(auth_header) = headers.get(AUTHORIZATION) {
        if let Ok(_token) = auth_header.to_str() {
            // In a real implementation, verify JWT and extract workspace_id here
            return Ok(next.run(req).await);
        }
    }
    
    // For now, fail if no authorization is provided to enforce isolation
    Err((axum::http::StatusCode::UNAUTHORIZED, "Missing or invalid authorization token".to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let config = Config::from_env();

    // Set up database pool
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    let app_state = AppState {
        db,
        github_token: config.github_token,
    };

    let origins: Vec<http::HeaderValue> = config.allowed_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(repo_risk_gate::amphoteric::handle_mcp_request))
        .merge(repo_risk_gate::router(app_state.clone()))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors)
                .layer(middleware::from_fn(auth_middleware)),
        )
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.gateway_port));
    tracing::info!("Governance Gateway listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "healthy" }))
}
