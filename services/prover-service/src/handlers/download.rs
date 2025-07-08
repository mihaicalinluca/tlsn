use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::io::Cursor;
use std::sync::Arc;
use tracing::{error, info, warn};
use zip::{write::FileOptions, ZipWriter};

use crate::{config::Config, session::SessionStore};

/// Download both attestation and secrets for a session as a ZIP file and cleanup immediately
pub async fn download_both(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!(
        "Download request for both attestation and secrets: {}",
        session_id
    );

    // Get both attestation and secrets data
    let attestation_data = session_store
        .get_attestation(&session_id)
        .await
        .map_err(|e| {
            error!(
                "Failed to get attestation for session {}: {}",
                session_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get attestation: {}", e),
            )
        })?;

    let secrets_data = session_store.get_secrets(&session_id).await.map_err(|e| {
        error!("Failed to get secrets for session {}: {}", session_id, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get secrets: {}", e),
        )
    })?;

    let attestation_data = attestation_data.ok_or_else(|| {
        warn!("Attestation not found for session: {}", session_id);
        (StatusCode::NOT_FOUND, "Attestation not found".to_string())
    })?;

    let secrets_data = secrets_data.ok_or_else(|| {
        warn!("Secrets not found for session: {}", session_id);
        (StatusCode::NOT_FOUND, "Secrets not found".to_string())
    })?;

    // Create ZIP file in memory
    let mut zip_buffer = Vec::new();
    {
        let cursor = Cursor::new(&mut zip_buffer);
        let mut zip = ZipWriter::new(cursor);

        // Add attestation file
        let attestation_filename = format!("attestation_{}.tlsn", session_id);
        zip.start_file(&attestation_filename, FileOptions::default())
            .map_err(|e| {
                error!("Failed to create attestation file in ZIP: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create ZIP file".to_string(),
                )
            })?;

        std::io::Write::write_all(&mut zip, &attestation_data).map_err(|e| {
            error!("Failed to write attestation data to ZIP: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write to ZIP file".to_string(),
            )
        })?;

        // Add secrets file
        let secrets_filename = format!("secrets_{}.tlsn", session_id);
        zip.start_file(&secrets_filename, FileOptions::default())
            .map_err(|e| {
                error!("Failed to create secrets file in ZIP: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create ZIP file".to_string(),
                )
            })?;

        std::io::Write::write_all(&mut zip, &secrets_data).map_err(|e| {
            error!("Failed to write secrets data to ZIP: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write to ZIP file".to_string(),
            )
        })?;

        zip.finish().map_err(|e| {
            error!("Failed to finish ZIP file: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to complete ZIP file".to_string(),
            )
        })?;
    }

    // Schedule immediate cleanup (remove from memory after successful download)
    let session_store_clone = Arc::clone(&session_store);
    let session_id_clone = session_id.clone();
    tokio::spawn(async move {
        if let Err(e) = session_store_clone.remove_session(&session_id_clone).await {
            error!(
                "Failed to cleanup session {} after both download: {}",
                session_id_clone, e
            );
        } else {
            info!(
                "Session {} cleaned up after both download",
                session_id_clone
            );
        }
    });

    // Return ZIP file
    let filename = format!("tlsn_session_{}.zip", session_id);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(zip_buffer))
        .map_err(|e| {
            error!("Failed to build response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response".to_string(),
            )
        })?;

    info!(
        "Both files download (ZIP) started for session: {}",
        session_id
    );
    Ok(response)
}

/// Download attestation for a session
pub async fn download_attestation(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("Download request for attestation: {}", session_id);

    // Get attestation data
    let attestation_data = session_store
        .get_attestation(&session_id)
        .await
        .map_err(|e| {
            error!(
                "Failed to get attestation for session {}: {}",
                session_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get attestation: {}", e),
            )
        })?;

    let attestation_data = attestation_data.ok_or_else(|| {
        warn!("Attestation not found for session: {}", session_id);
        (StatusCode::NOT_FOUND, "Attestation not found".to_string())
    })?;

    // No immediate cleanup - session will be cleaned up automatically after 10 minutes

    // Return attestation as downloadable file
    let filename = format!("attestation_{}.tlsn", session_id);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(attestation_data))
        .map_err(|e| {
            error!("Failed to build response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response".to_string(),
            )
        })?;

    info!("Attestation download started for session: {}", session_id);
    Ok(response)
}

/// Download secrets for a session
pub async fn download_secrets(
    State((_, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("Download request for secrets: {}", session_id);

    // Get secrets data
    let secrets_data = session_store.get_secrets(&session_id).await.map_err(|e| {
        error!("Failed to get secrets for session {}: {}", session_id, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get secrets: {}", e),
        )
    })?;

    let secrets_data = secrets_data.ok_or_else(|| {
        warn!("Secrets not found for session: {}", session_id);
        (StatusCode::NOT_FOUND, "Secrets not found".to_string())
    })?;

    // No immediate cleanup - session will be cleaned up automatically after 10 minutes

    // Return secrets as downloadable file
    let filename = format!("secrets_{}.tlsn", session_id);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(secrets_data))
        .map_err(|e| {
            error!("Failed to build response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response".to_string(),
            )
        })?;

    info!("Secrets download started for session: {}", session_id);
    Ok(response)
}
