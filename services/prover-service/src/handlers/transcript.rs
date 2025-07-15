use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use base64::prelude::*;
use std::sync::Arc;
use tracing::{error, info};

use tlsn_core::{attestation::Attestation, Secrets};
use tlsn_formats::http::HttpTranscript;
use tlsn_formats::spansy::Spanned;

use crate::{
    config::Config,
    session::{
        HttpHeaderInfo, HttpRequestInfo, HttpResponseInfo, HttpTranscriptResponse, SessionStatus,
        SessionStore,
    },
};

/// Get HTTP transcript data (headers and response body) for a completed session
pub async fn get_http_transcript(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<Json<HttpTranscriptResponse>, (StatusCode, String)> {
    info!("Getting HTTP transcript for session: {}", session_id);

    let session = session_store
        .get_session(&session_id)
        .await
        .ok_or_else(|| {
            error!("Session {} not found", session_id);
            (
                StatusCode::NOT_FOUND,
                format!("Session {} not found", session_id),
            )
        })?;

    let session_info = session.lock().await;

    // Check if session is completed
    if session_info.status != SessionStatus::Completed {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Session {} is not completed yet", session_id),
        ));
    }

    let (attestation_data, secrets_data) = match (&session_info.attestation, &session_info.secrets)
    {
        (Some(att), Some(sec)) => (att, sec),
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attestation or secrets data not found".to_string(),
            ));
        }
    };

    // Deserialize attestation and secrets
    let _attestation: Attestation = bincode::deserialize(attestation_data).map_err(|e| {
        error!("Failed to deserialize attestation: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to deserialize attestation: {}", e),
        )
    })?;

    let secrets: Secrets = bincode::deserialize(secrets_data).map_err(|e| {
        error!("Failed to deserialize secrets: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to deserialize secrets: {}", e),
        )
    })?;

    // Parse HTTP transcript from the secrets
    let http_transcript = HttpTranscript::parse(secrets.transcript()).map_err(|e| {
        error!("Failed to parse HTTP transcript: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse HTTP transcript: {}", e),
        )
    })?;

    // Extract request information (first request)
    let request_info = if let Some(request) = http_transcript.requests.first() {
        let method = request.request.method.as_str().to_string();
        let path = request.request.target.as_str().to_string();
        let headers = request
            .headers
            .iter()
            .map(|header| HttpHeaderInfo {
                name: header.name.as_str().to_string(),
                value: String::from_utf8_lossy(header.value.span().as_bytes()).to_string(),
            })
            .collect();

        HttpRequestInfo {
            method,
            path,
            headers,
        }
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "No HTTP request found in transcript".to_string(),
        ));
    };

    // Extract response information (first response)
    let response_info = if let Some(response) = http_transcript.responses.first() {
        let status_code = response.status.code.as_str().to_string();
        let status_text = response.status.reason.as_str().to_string();

        let headers = response
            .headers
            .iter()
            .map(|header| HttpHeaderInfo {
                name: header.name.as_str().to_string(),
                value: String::from_utf8_lossy(header.value.span().as_bytes()).to_string(),
            })
            .collect();

        let (body, body_size) = if let Some(body) = &response.body {
            let body_bytes = body.content.span().as_bytes();
            let body_size = body_bytes.len();

            // Try to decode as UTF-8 text first
            let body_str = if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
                // valid UTF-8, return as plain text
                text
            } else {
                // not valid UTF-8, encode as base64
                BASE64_STANDARD.encode(body_bytes)
            };

            (body_str, body_size)
        } else {
            (String::new(), 0)
        };

        HttpResponseInfo {
            status_code,
            status_text,
            headers,
            body,
            body_size,
        }
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "No HTTP response found in transcript".to_string(),
        ));
    };

    let transcript_response = HttpTranscriptResponse {
        session_id: session_info.id.clone(),
        request: request_info,
        response: response_info,
    };

    info!(
        "Successfully extracted HTTP transcript for session: {}",
        session_id
    );
    Ok(Json(transcript_response))
}
