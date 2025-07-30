use axum::{extract::State, http::StatusCode, response::Json};
use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::spawn;
use tracing::{error, info};
use url::Url;

use http_body_util::Full;
use hyper::{body::Bytes, HeaderMap, Request};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::{
    config::{Config, StreamingConfig},
    session::{SessionStatus, SessionStore, StartMpcRequest, StartMpcResponse},
};

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

/// HTTP handler for starting an MPC session
pub async fn start_mpc_handler(
    State((config, session_store)): State<(Arc<Config>, Arc<SessionStore>)>,
    Json(request): Json<StartMpcRequest>,
) -> Result<Json<StartMpcResponse>, (StatusCode, String)> {
    info!("Received start_mpc request for: {}", request.target_api);

    // Validate the target API URL
    let target_url = Url::parse(&request.target_api).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid target API URL: {}", e),
        )
    })?;

    if target_url.scheme() != "https" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Target API must use HTTPS".to_string(),
        ));
    }

    // Create a new session
    let session_id = session_store.create_session(request.clone()).await;

    info!(
        "Created session {} for target: {}",
        session_id, request.target_api
    );

    let config_clone = Arc::clone(&config);
    let session_store_clone = Arc::clone(&session_store);
    let session_id_clone = session_id.clone();
    let request_clone = request;

    // Spawn background task to perform MPC
    spawn(async move {
        if let Err(e) = perform_mpc_session(
            config_clone,
            session_store_clone.clone(),
            session_id_clone.clone(),
            request_clone,
        )
        .await
        {
            error!("MPC session failed: {}", e);
            // Set error status in session store
            if let Err(store_err) = session_store_clone
                .set_error(&session_id_clone, e.to_string())
                .await
            {
                error!("Failed to set error status: {}", store_err);
            }
        }
    });

    Ok(Json(StartMpcResponse {
        session_id,
        status: SessionStatus::Created,
        notary_session_id: None,
    }))
}

// Session cleanup is handled by the background cleanup task
// Individual downloads have no immediate cleanup, ZIP download has immediate cleanup
// This avoids race conditions and provides consistent behavior
async fn perform_mpc_session(
    config: Arc<Config>,
    session_store: Arc<SessionStore>,
    session_id: String,
    request: StartMpcRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting MPC session {}", session_id);

    session_store
        .update_status(
            &session_id,
            SessionStatus::MpcSetup,
            Some("setting_up_mpc".to_string()),
            Some(10),
        )
        .await
        .map_err(|e| format!("Failed to update session status: {}", e))?;

    let target_url = if !request.target_api.is_empty() {
        Url::parse(&request.target_api)?
    } else {
        info!(
            "Using default target URL from config: {}",
            config.target_server.default_host
        );
        Url::parse(&config.target_server.default_host)?
    };

    let server_name = target_url.host_str().ok_or("Invalid target URL: no host")?;
    let server_port = target_url.port().unwrap_or_else(|| {
        info!(
            "Using default port from config: {}",
            config.target_server.default_port
        );
        config.target_server.default_port
    });

    session_store
        .update_status(
            &session_id,
            SessionStatus::MpcSetup,
            Some("connecting_to_notary".to_string()),
            Some(20),
        )
        .await?;

    // Connect to notary server
    let notary_client = NotaryClient::builder()
        .host(&config.notary.host)
        .port(config.notary.port)
        .enable_tls(config.notary.tls_enabled)
        .build()?;

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(config.session.max_sent_data)
        .max_recv_data(config.session.max_recv_data)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: notary_session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .map_err(|e| format!("Failed to connect to notary: {}", e))?;

    // Update session with notary session ID
    session_store
        .update_notary_session_id(&session_id, notary_session_id.clone())
        .await?;

    session_store
        .update_status(
            &session_id,
            SessionStatus::MpcSetup,
            Some("mpc_preprocessing".to_string()),
            Some(40),
        )
        .await?;

    // Set up prover configuration
    let prover_config = ProverConfig::builder()
        .server_name(server_name)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(config.session.max_sent_data)
                .max_recv_data(config.session.max_recv_data)
                .build()?,
        )
        .build()?;

    // Create and setup prover
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    session_store
        .update_status(
            &session_id,
            SessionStatus::Connecting,
            Some("connecting_to_target".to_string()),
            Some(60),
        )
        .await?;

    // Connect to target server
    let client_socket = tokio::net::TcpStream::connect((server_name, server_port)).await?;

    // Bind prover to server connection
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn prover task
    let prover_task = tokio::spawn(prover_fut);

    session_store
        .update_status(
            &session_id,
            SessionStatus::Notarizing,
            Some("performing_request".to_string()),
            Some(70),
        )
        .await?;

    // Set up HTTP connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn HTTP task
    tokio::spawn(connection);

    // Build and send HTTP request
    let path = target_url.path();
    let query = target_url
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let uri = format!("{}{}", path, query);

    let parsed_method = request
        .method
        .parse::<hyper::Method>()
        .unwrap_or(hyper::Method::GET);

    let mut request_builder = Request::builder()
        .uri(&uri)
        .method(&parsed_method)
        .header("Host", server_name)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("Cache-Control", "no-cache");

    // Add custom headers if provided
    if let Some(headers) = &request.headers {
        for (key, value) in headers {
            request_builder = request_builder.header(key, value);
        }
    }

    // Handle request body for POST/PUT/PATCH methods
    let body_bytes = if let Some(body) = &request.body {
        // If body is provided, serialize it to JSON string
        let body_json = serde_json::to_string(body)
            .map_err(|e| format!("Failed to serialize body to JSON: {}", e))?;
        Bytes::from(body_json)
    } else {
        // For methods that typically need a body, provide empty JSON
        let method = request
            .method
            .parse::<hyper::Method>()
            .unwrap_or(hyper::Method::GET);
        if matches!(
            method,
            hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH
        ) {
            Bytes::from("{}")
        } else {
            // For GET, DELETE, HEAD, etc., use empty body
            Bytes::new()
        }
    };

    // Add Content-Type header if not already set and body is not empty
    if !body_bytes.is_empty() {
        let has_content_type = request
            .headers
            .as_ref()
            .map(|h| h.keys().any(|k| k.to_lowercase() == "content-type"))
            .unwrap_or(false);

        if !has_content_type {
            request_builder = request_builder.header("Content-Type", "application/json");
        }
    }

    let http_request = request_builder.body(Full::new(body_bytes.clone()))?;
    info!("Sending request: {:?}", http_request);

    // Always send the initial request first
    let mut response = request_sender.send_request(http_request).await?;
    let status = response.status();
    let headers = response.headers().clone();

    info!("Got response from server: {}", status);

    if status != StatusCode::OK {
        return Err(format!("Server returned status: {}", status).into());
    }

    // Check if this is a streaming response based on headers first
    let streaming_config = &config.streaming;
    let is_streaming_headers = is_streaming_response_headers(&headers);

    if is_streaming_headers {
        info!("Streaming response detected from headers - will consume entire stream");

        // For streaming responses, we need to consume the entire stream
        let complete_body = consume_streaming_response(&mut response, streaming_config).await?;

        info!(
            "Complete streaming response consumed: {} bytes",
            complete_body.len()
        );

        // Log preview of complete response
        let body_text = std::str::from_utf8(&complete_body).unwrap_or("");
        if !body_text.is_empty() {
            let preview = if body_text.len() > 500 {
                &body_text[..500]
            } else {
                body_text
            };
            info!("Complete response preview: {}...", preview);
        }
    } else {
        // For non-streaming responses, read normally
        let response_body = response.collect().await?;
        let body_bytes = response_body.to_bytes();

        info!("Response body size: {} bytes", body_bytes.len());

        // Convert to text for analysis
        let body_text = std::str::from_utf8(&body_bytes).unwrap_or("");

        // Log response content
        if !body_text.is_empty() {
            info!("Response body: {}...", body_text);
        } else {
            info!("Response body contains binary data");
        }

        // Double-check if this might be streaming based on content
        let is_streaming = detect_streaming_from_content(&headers, body_text, streaming_config);

        if is_streaming {
            info!(
                "Streaming response detected from content - but already consumed as single response"
            );
            info!("The response may still be arriving.");

            if body_text.contains("event:") && body_text.contains("data:") {
                info!("Server-Sent Events detected - this is a streaming response");
                info!("Note: SSE responses are designed to be consumed continuously");
            }
        } else {
            info!("Complete response received");
        }

        // Check for chunked encoding issues
        if let Some(transfer_encoding) = headers.get("transfer-encoding") {
            if let Ok(encoding_str) = transfer_encoding.to_str() {
                if encoding_str.contains("chunked") {
                    info!("IMPORTANT: This response uses chunked transfer encoding");
                }
            }
        }
    }

    session_store
        .update_status(
            &session_id,
            SessionStatus::Finalizing,
            Some("generating_attestation".to_string()),
            Some(85),
        )
        .await?;

    // Wait for prover task to complete
    let prover = prover_task.await??;

    // Start notarization process
    let mut prover = prover.start_notarize();

    // Check if we need to decode chunked transfer encoding before parsing
    let raw_transcript = prover.transcript();
    let received_data = raw_transcript.received();

    // Try to detect and decode chunked transfer encoding
    let processed_transcript = if is_chunked_response(received_data) {
        info!("Detected chunked transfer encoding in transcript - decoding before parsing");
        decode_chunked_transcript(raw_transcript)?
    } else {
        // Use original transcript
        raw_transcript.clone()
    };

    // Parse HTTP transcript from the (possibly processed) transcript
    let transcript = HttpTranscript::parse(&processed_transcript)?;

    // Commit to transcript
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    prover.transcript_commit(builder.build()?);

    // Build attestation request
    let request_config = RequestConfig::builder().build()?;

    // Update status: finalizing
    session_store
        .update_status(
            &session_id,
            SessionStatus::Finalizing,
            Some("finalizing_attestation".to_string()),
            Some(95),
        )
        .await?;

    // Generate final attestation and secrets
    let (attestation, secrets) = prover.finalize(&request_config).await?;

    // Serialize attestation and secrets
    let attestation_bytes = bincode::serialize(&attestation)?;
    let secrets_bytes = bincode::serialize(&secrets)?;

    // Store results
    session_store
        .set_attestation(&session_id, attestation_bytes, secrets_bytes)
        .await?;

    session_store
        .update_status(
            &session_id,
            SessionStatus::Completed,
            Some("completed".to_string()),
            Some(100),
        )
        .await?;

    info!("MPC session {} completed successfully", session_id);
    Ok(())
}

/// Detects if response content suggests it might be incomplete/streaming
fn detect_streaming_from_content(
    headers: &HeaderMap,
    body_text: &str,
    streaming_config: &StreamingConfig,
) -> bool {
    if body_text == "Streaming" || body_text == "Body(Streaming)" {
        info!("Streaming response detected - sending additional requests within same TLS session");
        return true;
    }

    // Check for Server-Sent Events (the most common streaming pattern)
    if body_text.contains("event:") && body_text.contains("data:") {
        info!("Server-Sent Events (SSE) streaming detected");
        return true;
    }

    // Check for chunked transfer encoding
    if let Some(transfer_encoding) = headers.get("transfer-encoding") {
        if let Ok(encoding_str) = transfer_encoding.to_str() {
            if encoding_str.contains("chunked") {
                info!("Chunked transfer encoding detected");
                return true;
            }
        }
    }

    // Check for text/event-stream content type (SSE)
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(content_type_str) = content_type.to_str() {
            if content_type_str.contains("text/event-stream") {
                info!("text/event-stream content type detected");
                return true;
            }
        }
    }

    // Check for Anthropic specific headers
    if headers.get("anthropic-ratelimit-requests-limit").is_some()
        || headers.get("request-id").is_some()
            && headers
                .get("content-type")
                .map(|v| v.to_str().unwrap_or("").contains("application/json"))
                .unwrap_or(false)
    {
        // For Anthropic API, check if there's a content-length header
        if let Some(content_length) = headers.get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    if length > 0 && body_text.len() >= length {
                        info!("Anthropic API response with content-length: {} - appears complete (got {} bytes)", length, body_text.len());
                        return false;
                    }
                }
            }
        }

        info!("Anthropic API response - checking content completeness");
    }

    // Check custom streaming headers if provided
    if !streaming_config.custom_streaming_headers.is_empty() {
        for header_name in &streaming_config.custom_streaming_headers {
            if headers.get(header_name).is_some() {
                info!("Detected streaming via custom header: {}", header_name);
                return true;
            }
        }
    }

    // Check for incomplete JSON responses
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(content_type_str) = content_type.to_str() {
            if content_type_str.contains("application/json") {
                // Check if JSON appears incomplete
                if body_text.trim().is_empty() {
                    info!("Empty JSON response body - likely incomplete");
                    return true;
                }

                // Check for incomplete JSON (doesn't end with } or ])
                let trimmed = body_text.trim();
                if !trimmed.ends_with('}') && !trimmed.ends_with(']') {
                    info!("Incomplete JSON response - doesn't end properly");
                    return true;
                }

                // For AI APIs, check for incomplete response patterns
                if trimmed.contains("\"finish_reason\": null")
                    || trimmed.contains("\"stop_reason\": null")
                {
                    info!("AI API response indicates streaming in progress");
                    return true;
                }

                // If we have substantial valid JSON content, it's probably complete
                if trimmed.len() > 100 && (trimmed.starts_with('{') || trimmed.starts_with('[')) {
                    info!("Substantial valid JSON content - appears complete");
                    return false;
                }
            }
        }
    }

    // Default to not streaming
    false
}

/// Checks headers to determine if this is a streaming response
fn is_streaming_response_headers(headers: &HeaderMap) -> bool {
    // Check for chunked transfer encoding
    if let Some(transfer_encoding) = headers.get("transfer-encoding") {
        if let Ok(encoding_str) = transfer_encoding.to_str() {
            if encoding_str.contains("chunked") {
                info!("Chunked transfer encoding detected");
                // Return false to avoid our streaming consumption logic
                return false;
            }
        }
    }

    // Check for text/event-stream content type (SSE)
    if let Some(content_type) = headers.get("content-type") {
        if let Ok(content_type_str) = content_type.to_str() {
            if content_type_str.contains("text/event-stream") {
                info!("text/event-stream content type detected in headers");

                // Also check if it's chunked - if so, warn and skip streaming consumption
                if let Some(transfer_encoding) = headers.get("transfer-encoding") {
                    if let Ok(encoding_str) = transfer_encoding.to_str() {
                        if encoding_str.contains("chunked") {
                            info!("WARNING: SSE with chunked encoding - TLSNotary limitation");
                            return false;
                        }
                    }
                }
                return true;
            }
        }
    }

    // Check for streaming-specific headers (but not chunked)
    if headers
        .get("x-accel-buffering")
        .map(|v| v.to_str().unwrap_or("") == "no")
        .unwrap_or(false)
    {
        // Make sure it's not also chunked
        if let Some(transfer_encoding) = headers.get("transfer-encoding") {
            if let Ok(encoding_str) = transfer_encoding.to_str() {
                if encoding_str.contains("chunked") {
                    info!(
                        "WARNING: Streaming headers with chunked encoding - TLSNotary limitation"
                    );
                    return false;
                }
            }
        }
        info!("Streaming headers detected (x-accel-buffering: no)");
        return true;
    }

    false
}

/// Consumes a streaming response completely by reading all chunks
async fn consume_streaming_response(
    response: &mut hyper::Response<hyper::body::Incoming>,
    streaming_config: &StreamingConfig,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut complete_body = Vec::new();
    let mut chunks_received = 0;
    let start_time = Instant::now();
    let timeout = Duration::from_secs(streaming_config.request_timeout_secs);

    info!("Starting to consume streaming response...");

    let body = response.body_mut();

    loop {
        // Check for timeout
        if start_time.elapsed() > timeout {
            info!(
                "Streaming response timeout after {} seconds, stopping consumption",
                streaming_config.request_timeout_secs
            );
            break;
        }

        // Try to get the next frame with a timeout
        let frame_result = tokio::time::timeout(
            Duration::from_secs(5), // 5 second timeout per chunk
            body.frame(),
        )
        .await;

        match frame_result {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    complete_body.extend_from_slice(data);
                    chunks_received += 1;

                    info!(
                        "Received chunk {}: {} bytes (total: {} bytes)",
                        chunks_received,
                        data.len(),
                        complete_body.len()
                    );

                    // Check if we've reached a reasonable size limit
                    // TODO: This will be the same as the max_recv_data in the config
                    if complete_body.len() > 20_000_000 {
                        // 20MB limit
                        info!("Response size limit reached (10MB), stopping consumption");
                        break;
                    }
                }

                // For hyper frames, we check if the frame has trailers or indicates end
                if frame.is_trailers() {
                    info!("Trailers received - end of stream");
                    break;
                }
            }
            Ok(Some(Err(e))) => {
                info!("Error reading stream chunk: {}", e);
                break;
            }
            Ok(None) => {
                info!("Stream ended (no more frames)");
                break;
            }
            Err(_) => {
                info!("Chunk timeout (5s), checking if stream is complete");
                // For SSE, a timeout might just mean the server is thinking
                // Check if we have a reasonable amount of data
                if chunks_received > 0 {
                    info!(
                        "Received {} chunks, assuming stream may be complete",
                        chunks_received
                    );
                    break;
                }
            }
        }
    }

    let elapsed = start_time.elapsed();
    info!(
        "Streaming consumption completed: {} chunks, {} bytes in {:.2}s",
        chunks_received,
        complete_body.len(),
        elapsed.as_secs_f64()
    );

    Ok(complete_body)
}

/// Detects if the HTTP response uses chunked transfer encoding
fn is_chunked_response(received_data: &[u8]) -> bool {
    // Convert bytes to string to search for HTTP headers
    if let Ok(response_str) = std::str::from_utf8(received_data) {
        // Look for the Transfer-Encoding header in the HTTP response
        let lines = response_str.lines();
        for line in lines {
            if line.is_empty() {
                // End of headers, stop looking
                break;
            }
            if line.to_lowercase().starts_with("transfer-encoding:")
                && line.to_lowercase().contains("chunked")
            {
                return true;
            }
        }
    }
    false
}

/// Decodes chunked transfer encoding from the raw transcript
fn decode_chunked_transcript(
    transcript: &tlsn_core::transcript::Transcript,
) -> Result<tlsn_core::transcript::Transcript, Box<dyn std::error::Error + Send + Sync>> {
    let sent_data = transcript.sent().to_vec();
    let received_data = transcript.received();

    info!(
        "Decoding chunked transcript, received data length: {} bytes",
        received_data.len()
    );

    // Parse the HTTP response to separate headers from body
    if let Ok(response_str) = std::str::from_utf8(received_data) {
        // Find the double CRLF that separates headers from body
        let header_end = if let Some(pos) = response_str.find("\r\n\r\n") {
            pos + 4 // Include the \r\n\r\n
        } else if let Some(pos) = response_str.find("\n\n") {
            pos + 2 // Include the \n\n
        } else {
            return Err("Could not find end of HTTP headers".into());
        };

        let headers_str = &response_str[..header_end];
        let body_start_idx = header_end;

        // Parse headers into lines
        let headers: Vec<&str> = headers_str.lines().collect();

        info!(
            "Found {} header lines, body starts at byte {}",
            headers.len(),
            body_start_idx
        );

        // Log some headers for debugging
        for (i, header) in headers.iter().take(10).enumerate() {
            info!("Header {}: {:?}", i, header);
        }

        // The body starts after the double CRLF
        let body_bytes = &received_data[body_start_idx..];
        info!("Chunked body length: {} bytes", body_bytes.len());

        // Show first 200 bytes of chunked body for debugging
        let preview_len = std::cmp::min(200, body_bytes.len());
        let body_preview =
            std::str::from_utf8(&body_bytes[..preview_len]).unwrap_or("<binary data>");
        info!(
            "Chunked body preview (first {} bytes): {:?}",
            preview_len, body_preview
        );

        // Decode chunked body
        let decoded_body = decode_chunked_body(body_bytes)?;

        // Reconstruct the HTTP response with decoded body
        let mut new_headers = Vec::new();
        for header in &headers {
            if !header.to_lowercase().starts_with("transfer-encoding:") && !header.is_empty() {
                new_headers.push(header.to_string());
            }
        }

        // Add Content-Length header
        new_headers.push(format!("Content-Length: {}", decoded_body.len()));

        // Combine headers with proper CRLF line endings and add final separator
        let headers_text = new_headers.join("\r\n");
        let mut new_response = headers_text.into_bytes();
        new_response.extend_from_slice(b"\r\n\r\n"); // Double CRLF to separate headers from body
        new_response.extend_from_slice(&decoded_body);

        // Store the length before moving new_response
        let new_response_len = new_response.len();

        // Create new transcript with the decoded response
        use tlsn_core::transcript::Transcript;
        let new_transcript = Transcript::new(sent_data, new_response);

        info!(
            "Successfully decoded chunked response: {} -> {} bytes",
            received_data.len(),
            new_response_len
        );

        Ok(new_transcript)
    } else {
        Err("Failed to parse HTTP response as UTF-8".into())
    }
}

/// Decodes HTTP chunked transfer encoding
fn decode_chunked_body(
    chunked_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut decoded = Vec::new();
    let mut pos = 0;

    info!(
        "Starting chunked decoding, data length: {} bytes",
        chunked_data.len()
    );

    while pos < chunked_data.len() {
        // Find the chunk size line (ends with \r\n or \n)
        let chunk_size_end = chunked_data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| p + pos + 2)
            .or_else(|| {
                chunked_data[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| p + pos + 1)
            });

        let chunk_size_end = match chunk_size_end {
            Some(end) => end,
            None => {
                info!("No more chunk size markers found at position {}", pos);
                break; // No more complete chunks
            }
        };

        // Extract chunk size line
        let chunk_size_line = if chunked_data[chunk_size_end - 2..chunk_size_end] == *b"\r\n" {
            &chunked_data[pos..chunk_size_end - 2]
        } else {
            &chunked_data[pos..chunk_size_end - 1]
        };

        let chunk_size_str = std::str::from_utf8(chunk_size_line)
            .map_err(|e| format!("Invalid UTF-8 in chunk size line: {}", e))?;

        info!("Chunk size line: {:?}", chunk_size_str);

        // Parse chunk size (hexadecimal) - handle chunk extensions
        let chunk_size_clean = chunk_size_str
            .split(';') // Remove chunk extensions like "a1;charset=utf-8"
            .next()
            .unwrap_or("")
            .trim();

        info!("Parsing chunk size: {:?}", chunk_size_clean);

        let chunk_size = usize::from_str_radix(chunk_size_clean, 16).map_err(|e| {
            format!(
                "Failed to parse chunk size '{}' as hex: {}",
                chunk_size_clean, e
            )
        })?;

        info!("Parsed chunk size: {} bytes", chunk_size);

        // If chunk size is 0, we've reached the end
        if chunk_size == 0 {
            info!("Reached end chunk (size 0)");
            break;
        }

        // Extract the chunk data
        let chunk_start = chunk_size_end;
        let chunk_end = chunk_start + chunk_size;

        if chunk_end <= chunked_data.len() {
            decoded.extend_from_slice(&chunked_data[chunk_start..chunk_end]);
            info!(
                "Decoded chunk: {} bytes (total so far: {} bytes)",
                chunk_size,
                decoded.len()
            );

            // Skip the chunk data and trailing CRLF
            pos = chunk_end;

            // Skip trailing \r\n after chunk data
            if pos + 1 < chunked_data.len() && chunked_data[pos..pos + 2] == *b"\r\n" {
                pos += 2;
            } else if pos < chunked_data.len() && chunked_data[pos] == b'\n' {
                pos += 1;
            }
        } else {
            info!(
                "Incomplete chunk detected at position {}, expected {} bytes but only {} available",
                pos,
                chunk_size,
                chunked_data.len() - chunk_start
            );
            break; // Incomplete chunk
        }
    }

    info!(
        "Chunked decoding complete: {} total bytes decoded",
        decoded.len()
    );
    Ok(decoded)
}
