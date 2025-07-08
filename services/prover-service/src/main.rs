mod config;
mod handlers;
mod session;

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, time::interval};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use config::Config;
use handlers::{
    attestation::get_attestation,
    mpc::start_mpc_handler,
    status::{get_session_status, list_sessions},
};
use session::SessionStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::load()?;
    info!("Configuration loaded successfully");

    let log_level = match config.logging.level.to_uppercase().as_str() {
        "TRACE" => tracing::Level::TRACE,
        "DEBUG" => tracing::Level::DEBUG,
        "INFO" => tracing::Level::INFO,
        "WARN" => tracing::Level::WARN,
        "ERROR" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(log_level).init();

    info!("Logging level set to: {}", config.logging.level);

    if let Err(e) = config.fetch_notary_config().await {
        warn!("Failed to fetch notary config: {}, using local config", e);
    }

    let session_store = Arc::new(SessionStore::new());

    // Start background cleanup task
    {
        let session_store_clone = Arc::clone(&session_store);
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(3600)); // Clean up every hour
            loop {
                cleanup_interval.tick().await;
                session_store_clone.cleanup_old_sessions().await;
                info!("Cleaned up old sessions");
            }
        });
    }

    let config_arc = Arc::new(config);

    // Create application router
    let app = create_app(Arc::clone(&config_arc), Arc::clone(&session_store)).await;

    // Start server
    let bind_address = format!("{}:{}", config_arc.server.host, config_arc.server.port);
    let listener = TcpListener::bind(&bind_address).await?;

    info!("  Prover service starting on {}", bind_address);
    info!("  API endpoints:");
    info!("  POST /start_mpc - Start MPC session");
    info!("  GET  /status/:session_id - Get session status");
    info!("  GET  /sessions - List all sessions");
    info!("  GET  /attestation/:session_id - Get attestation");
    info!("  GET  /health - Health check");
    info!("  GET  /info - Service information");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_app(config: Arc<Config>, session_store: Arc<SessionStore>) -> Router {
    Router::new()
        .route("/start_mpc", post(start_mpc_handler))
        .route("/status/:session_id", get(get_session_status))
        .route("/sessions", get(list_sessions))
        .route("/attestation/:session_id", get(get_attestation))
        .route("/health", get(health_check))
        .route("/info", get(service_info))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state((config, session_store))
}

/// Health check endpoint
async fn health_check() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "status": "healthy",
        "service": "tlsn-prover-service",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Service information endpoint
async fn service_info(
    State((config, _)): State<(Arc<Config>, Arc<SessionStore>)>,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "service": "tlsn-prover-service",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "HTTP service wrapper for TLSNotary prover functionality",
        "notary": {
            "host": config.notary.host,
            "port": config.notary.port,
            "tls_enabled": config.notary.tls_enabled,
            "timeout": config.notary.timeout
        },
        "session_limits": {
            "max_sent_data": config.session.max_sent_data,
            "max_recv_data": config.session.max_recv_data
        }
    })))
}
