use axum::{extract::State, http::StatusCode, response::Json};
use std::sync::Arc;
use tokio::spawn;
use tracing::{error, info};
use url::Url;

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode as HyperStatusCode};
use hyper_util::rt::TokioIo;
use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::{
    config::Config,
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

    let target_url = Url::parse(&request.target_api)?;
    let server_name = target_url.host_str().ok_or("Invalid target URL: no host")?;
    let server_port = target_url.port().unwrap_or(443);

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

    let mut request_builder = Request::builder()
        .uri(uri)
        .header("Host", server_name)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);

    // Add custom headers if provided
    if let Some(headers) = &request.headers {
        for (key, value) in headers {
            request_builder = request_builder.header(key, value);
        }
    }

    let http_request = request_builder.body(Empty::<Bytes>::new())?;

    // Send request and get response
    let response = request_sender.send_request(http_request).await?;

    info!("Got response from server: {}", response.status());

    if response.status() != HyperStatusCode::OK {
        return Err(format!("Server returned status: {}", response.status()).into());
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

    // Parse HTTP transcript
    let transcript = HttpTranscript::parse(prover.transcript())?;

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
