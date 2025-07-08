use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use base64::prelude::*;
use std::sync::Arc;
use tracing::info;

use crate::{
    config::Config,
    session::{AttestationResponse, SessionStatus, SessionStore, TranscriptPreview},
};

/// Get attestation for a completed session
pub async fn get_attestation(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<Json<AttestationResponse>, (StatusCode, String)> {
    info!("Getting attestation for session: {}", session_id);

    if let Some(session) = session_store.get_session(&session_id).await {
        let session_info = session.lock().await;

        // Check if session is completed
        if session_info.status != SessionStatus::Completed {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Session {} is not completed yet", session_id),
            ));
        }

        let session_config = Config::load().unwrap().session;

        if let (Some(attestation), Some(secrets)) =
            (&session_info.attestation, &session_info.secrets)
        {
            let transcript_preview = TranscriptPreview {
                sent_data_size: session_config.max_sent_data,
                received_data_size: session_config.max_recv_data,
                target_server: session_info.request.target_api.clone(),
            };

            Ok(Json(AttestationResponse {
                session_id: session_info.id.clone(),
                attestation: BASE64_STANDARD.encode(attestation),
                secrets: BASE64_STANDARD.encode(secrets),
                transcript_preview,
            }))
        } else {
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attestation data not found".to_string(),
            ))
        }
    } else {
        Err((
            StatusCode::NOT_FOUND,
            format!("Session {} not found", session_id),
        ))
    }
}
