use axum::{
    routing::{get, post},
    Router,
    response::IntoResponse,
    Json,
};
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tower::ServiceBuilder;
use sqlx::postgres::PgPoolOptions;

mod config;
mod repo_risk_gate;

use config::Config;
use repo_risk_gate::AppState;

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

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/mcp", post(mcp_handler))
        .merge(repo_risk_gate::router(app_state.clone()))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
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

async fn mcp_handler(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    Json(serde_json::json!({ "status": "processed", "payload": payload }))
}
