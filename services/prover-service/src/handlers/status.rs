use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use std::sync::Arc;
use tracing::info;

use crate::{
    config::Config,
    session::{SessionStore, SessionStatusResponse, SessionListResponse},
};

/// Get status of a specific session
pub async fn get_session_status(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, String)> {
    info!("Getting status for session: {}", session_id);

    if let Some(session) = session_store.get_session(&session_id).await {
        let session_info = session.lock().await;
        
        Ok(Json(SessionStatusResponse {
            session_id: session_info.id.clone(),
            status: session_info.status.clone(),
            progress: session_info.progress.clone(),
            error: session_info.error.clone(),
        }))
    } else {
        Err((StatusCode::NOT_FOUND, format!("Session {} not found", session_id)))
    }
}

/// List all sessions
pub async fn list_sessions(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
) -> Result<Json<SessionListResponse>, (StatusCode, String)> {
    info!("Listing all sessions");

    let sessions = session_store.list_sessions().await;
    
    Ok(Json(SessionListResponse {
        sessions,
    }))
} 