use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{sync::Arc, time::Duration};
use tlsn_core::{
    attestation::Attestation,
    presentation::{Presentation, PresentationOutput},
    signing::VerifyingKey,
    CryptoProvider, Secrets,
};

use tracing::{debug, error, info};

use crate::{
    config::Config,
    session::{
        SessionStatus, SessionStore, TranscriptSummary, VerificationDetails, VerifyDataRequest,
        VerifyPresentationResponse, VerifyingKeyInfo,
    },
};

/// Extract detailed information from successful verification
fn extract_verification_details(
    output: PresentationOutput,
    verifying_key_info: VerifyingKeyInfo,
) -> VerificationDetails {
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = output;

    // Format the connection time
    let connection_time = {
        let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
        time.to_rfc3339()
    };

    let server_name = server_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract transcript summary if available
    let transcript_summary = transcript.map(|mut transcript| {
        // Set unauthenticated bytes so they are distinguishable (same as example)
        transcript.set_unauthed(b'X');

        let sent_data = transcript.sent_unsafe();
        let received_data = transcript.received_unsafe();

        // Create safe previews (limit to 200 chars and mask potentially sensitive data)
        let sent_preview = create_safe_preview(&sent_data, 200);
        let recv_preview = create_safe_preview(&received_data, 200);

        debug!(
            "Transcript summary - Sent: {} bytes, Received: {} bytes",
            sent_data.len(),
            received_data.len()
        );

        TranscriptSummary {
            sent_data_size: sent_data.len(),
            received_data_size: received_data.len(),
            sent_data_preview: sent_preview,
            received_data_preview: recv_preview,
        }
    });

    VerificationDetails {
        server_name,
        connection_time,
        verifying_key: verifying_key_info,
        transcript_summary,
    }
}

/// Create a safe preview of data, masking potentially sensitive information
/// and limiting the length to prevent overwhelming responses
fn create_safe_preview(data: &[u8], max_chars: usize) -> String {
    // Convert to string, handling invalid UTF-8 gracefully
    let text = String::from_utf8_lossy(data);

    // Truncate to max_chars
    let truncated = if text.len() > max_chars {
        format!("{}... (truncated)", &text[..max_chars])
    } else {
        text.to_string()
    };

    // Basic masking of common sensitive patterns - only if they exist
    let mut masked = truncated;

    // Only mask if these environment variables are actually set and non-empty
    if let Ok(openai_key) = std::env::var("OPENAI_API_KEY") {
        if !openai_key.is_empty() && openai_key.len() > 5 {
            masked = masked.replace(&openai_key, "[MASKED_OPENAI_KEY]");
        }
    }

    if let Ok(anthropic_key) = std::env::var("ANTHROPIC_API_KEY") {
        if !anthropic_key.is_empty() && anthropic_key.len() > 5 {
            masked = masked.replace(&anthropic_key, "[MASKED_ANTHROPIC_KEY]");
        }
    }

    // Mask Authorization headers but preserve the rest
    let lines: Vec<&str> = masked.lines().collect();
    let processed_lines: Vec<String> = lines
        .into_iter()
        .map(|line| {
            let lower_line = line.to_lowercase();
            if lower_line.starts_with("authorization:") {
                "Authorization: [MASKED]".to_string()
            } else if lower_line.starts_with("cookie:") {
                "Cookie: [MASKED]".to_string()
            } else if lower_line.starts_with("x-api-key:") {
                "X-API-Key: [MASKED]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();

    processed_lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_safe_preview() {
        let data = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret123\r\n\r\n";
        let preview = create_safe_preview(data, 100);

        assert!(preview.contains("[MASKED]"));
        assert!(preview.contains("GET /api/test"));
        assert!(!preview.contains("secret123"));
    }

    #[test]
    fn test_create_safe_preview_truncation() {
        let data = b"This is a very long string that should be truncated because it exceeds the maximum character limit";
        let preview = create_safe_preview(data, 20);

        assert!(preview.contains("truncated"));
        assert!(preview.len() < 50); // Should be much shorter than original
    }
}

/// Verify a session's attestation and secrets by session ID
///
/// This endpoint verifies the MPC session data while the files are still available.
/// Perfect for verification before downloading files.
pub async fn verify_session_handler(
    Path(session_id): Path<String>,
    State((_config, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
) -> Result<Json<VerifyPresentationResponse>, StatusCode> {
    info!(
        "Received session verification request for session: {}",
        session_id
    );

    // Get session from store
    let session = match session_store.get_session(&session_id).await {
        Some(session) => session,
        None => {
            error!("Session {} not found", session_id);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Session {} not found", session_id)),
                verification_details: None,
            }));
        }
    };

    let session_info = session.lock().await;

    // Check if session is completed
    if session_info.status != SessionStatus::Completed {
        return Ok(Json(VerifyPresentationResponse {
            verified: false,
            error: Some(format!(
                "Session {} is not completed (status: {:?})",
                session_id, session_info.status
            )),
            verification_details: None,
        }));
    }

    // Check if attestation and secrets are available
    let (attestation_data, secrets_data) = match (&session_info.attestation, &session_info.secrets)
    {
        (Some(att), Some(sec)) => (att.clone(), sec.clone()),
        _ => {
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!(
                    "Session {} files are no longer available",
                    session_id
                )),
                verification_details: None,
            }));
        }
    };

    drop(session_info); // Release the lock

    debug!(
        "Found session data - Attestation: {} bytes, Secrets: {} bytes",
        attestation_data.len(),
        secrets_data.len()
    );

    // Verify using the attestation and secrets data
    verify_from_attestation_and_secrets(attestation_data, secrets_data).await
}

/// This endpoint accepts base64-encoded attestation and secrets data,
/// builds a presentation, and verifies it. Perfect for verification after downloading files.
pub async fn verify_data_handler(
    State((_config, _session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Json(request): Json<VerifyDataRequest>,
) -> Result<Json<VerifyPresentationResponse>, StatusCode> {
    info!("Received data verification request");
    debug!(
        "Attestation data length: {} chars, Secrets data length: {} chars",
        request.attestation_data.len(),
        request.secrets_data.len()
    );

    // Decode the base64 attestation data
    let attestation_bytes = match STANDARD.decode(&request.attestation_data) {
        Ok(bytes) => {
            debug!(
                "Successfully decoded base64 attestation data: {} bytes",
                bytes.len()
            );
            bytes
        }
        Err(e) => {
            error!("Failed to decode base64 attestation data: {}", e);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Invalid base64 encoding for attestation: {}", e)),
                verification_details: None,
            }));
        }
    };

    // Decode the base64 secrets data
    let secrets_bytes = match STANDARD.decode(&request.secrets_data) {
        Ok(bytes) => {
            debug!(
                "Successfully decoded base64 secrets data: {} bytes",
                bytes.len()
            );
            bytes
        }
        Err(e) => {
            error!("Failed to decode base64 secrets data: {}", e);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Invalid base64 encoding for secrets: {}", e)),
                verification_details: None,
            }));
        }
    };

    verify_from_attestation_and_secrets(attestation_bytes, secrets_bytes).await
}

/// Common verification logic for both session and data endpoints
async fn verify_from_attestation_and_secrets(
    attestation_bytes: Vec<u8>,
    secrets_bytes: Vec<u8>,
) -> Result<Json<VerifyPresentationResponse>, StatusCode> {
    // Deserialize the attestation
    let attestation: Attestation = match bincode::deserialize(&attestation_bytes) {
        Ok(att) => {
            debug!("Successfully deserialized attestation");
            att
        }
        Err(e) => {
            error!("Failed to deserialize attestation: {}", e);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Invalid attestation format: {}", e)),
                verification_details: None,
            }));
        }
    };

    // Deserialize the secrets
    let secrets: Secrets = match bincode::deserialize(&secrets_bytes) {
        Ok(sec) => {
            debug!("Successfully deserialized secrets");
            sec
        }
        Err(e) => {
            error!("Failed to deserialize secrets: {}", e);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Invalid secrets format: {}", e)),
                verification_details: None,
            }));
        }
    };

    // Build presentation from attestation and secrets
    let presentation =
        match build_presentation_from_attestation_and_secrets(&attestation, &secrets).await {
            Ok(pres) => {
                debug!("Successfully built presentation");
                pres
            }
            Err(e) => {
                error!("Failed to build presentation: {}", e);
                return Ok(Json(VerifyPresentationResponse {
                    verified: false,
                    error: Some(format!("Failed to build presentation: {}", e)),
                    verification_details: None,
                }));
            }
        };

    // Now verify the presentation using existing logic
    verify_presentation_internal(presentation).await
}

/// Build a presentation from attestation and secrets
async fn build_presentation_from_attestation_and_secrets(
    attestation: &Attestation,
    secrets: &Secrets,
) -> Result<Presentation, Box<dyn std::error::Error + Send + Sync>> {
    // Build a transcript proof
    let mut builder = secrets.transcript_proof_builder();

    let transcript = secrets.transcript();

    debug!(
        "Transcript lengths - Sent: {} bytes, Received: {} bytes",
        transcript.sent().len(),
        transcript.received().len()
    );

    // Try to reveal sent data only if it exists and was committed
    if transcript.sent().len() > 0 {
        debug!(
            "Attempting to reveal entire sent transcript: {} bytes",
            transcript.sent().len()
        );
        match builder.reveal_sent(&(0..transcript.sent().len())) {
            Ok(_) => {
                debug!("Successfully revealed sent transcript");
            }
            Err(e) => {
                debug!(
                    "Failed to reveal sent transcript: {}, skipping sent data",
                    e
                );
                // Don't return error, just skip sent data revelation
            }
        }
    }

    // Try to reveal received data only if it exists and was committed
    if transcript.received().len() > 0 {
        debug!(
            "Attempting to reveal entire received transcript: {} bytes",
            transcript.received().len()
        );
        match builder.reveal_recv(&(0..transcript.received().len())) {
            Ok(_) => {
                debug!("Successfully revealed received transcript");
            }
            Err(e) => {
                debug!(
                    "Failed to reveal received transcript: {}, skipping received data",
                    e
                );
                // skip received data revelation
            }
        }
    }

    // Build the proof with whatever we could reveal
    let transcript_proof = builder.build()?;

    // Use default crypto provider to build the presentation
    let provider = CryptoProvider::default();

    let mut presentation_builder = attestation.presentation_builder(&provider);

    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation = presentation_builder.build()?;

    Ok(presentation)
}

/// Internal presentation verification logic
async fn verify_presentation_internal(
    presentation: Presentation,
) -> Result<Json<VerifyPresentationResponse>, StatusCode> {
    // Get the crypto provider - production uses default
    let provider = CryptoProvider::default();

    // Extract verifying key information before verification
    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    let verifying_key_info = VerifyingKeyInfo {
        algorithm: alg.to_string(),
        key_data: hex::encode(key_data),
    };

    info!(
        "Verifying presentation with {} key: {}",
        alg,
        hex::encode(key_data)
    );

    // Perform the verification
    let verification_result = match presentation.verify(&provider) {
        Ok(output) => {
            info!("Presentation verification successful");
            output
        }
        Err(e) => {
            error!("Presentation verification failed: {}", e);
            return Ok(Json(VerifyPresentationResponse {
                verified: false,
                error: Some(format!("Verification failed: {}", e)),
                verification_details: None,
            }));
        }
    };

    // Extract verification details
    let verification_details =
        extract_verification_details(verification_result, verifying_key_info);

    info!(
        "Presentation verified successfully for server: {}",
        verification_details.server_name
    );

    Ok(Json(VerifyPresentationResponse {
        verified: true,
        error: None,
        verification_details: Some(verification_details),
    }))
}
