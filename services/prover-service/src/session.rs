use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Status of an MPC session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Session has been created but not started
    Created,
    /// MPC setup is in progress
    MpcSetup,
    /// Connecting to target server
    Connecting,
    /// Currently performing notarization
    Notarizing,
    /// Finalizing the attestation
    Finalizing,
    /// Session completed successfully
    Completed,
    /// Session failed with an error
    Failed,
}

/// Progress information for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProgress {
    pub stage: String,
    pub percentage: u8,
}

/// Request to start an MPC session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartMpcRequest {
    pub target_api: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default = "default_method")]
    pub method: String,
    pub session_id: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Response when starting an MPC session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartMpcResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub notary_session_id: Option<String>,
}

/// Session information stored in memory
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub status: SessionStatus,
    pub request: StartMpcRequest,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub progress: SessionProgress,
    pub notary_session_id: Option<String>,
    pub attestation: Option<Vec<u8>>,
    pub secrets: Option<Vec<u8>>,
}

/// Response for session status queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub status: SessionStatus,
    pub progress: SessionProgress,
    pub error: Option<String>,
}

/// Response containing session attestation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub session_id: String,
    pub attestation: String, // base64 encoded
    pub secrets: String,     // base64 encoded
    pub transcript_preview: TranscriptPreview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptPreview {
    pub sent_data_size: usize,
    pub received_data_size: usize,
    pub target_server: String,
}

/// Response for listing sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionSummary>,
}

/// Summary of a session for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub status: SessionStatus,
    pub target_api: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Response containing HTTP transcript data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTranscriptResponse {
    pub session_id: String,
    pub request: HttpRequestInfo,
    pub response: HttpResponseInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub headers: Vec<HttpHeaderInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseInfo {
    pub status_code: String,
    pub status_text: String,
    pub headers: Vec<HttpHeaderInfo>,
    pub body: String, // Base64 encoded for binary data, or plain text for text data
    pub body_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderInfo {
    pub name: String,
    pub value: String,
}

/// In-memory session store
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Arc<Mutex<SessionInfo>>>>>,
}

impl SessionStore {
    /// Create a new session store
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session
    pub async fn create_session(&self, request: StartMpcRequest) -> String {
        let session_id = request
            .session_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let session_info = SessionInfo {
            id: session_id.clone(),
            status: SessionStatus::Created,
            request,
            created_at: Utc::now(),
            completed_at: None,
            error: None,
            progress: SessionProgress {
                stage: "created".to_string(),
                percentage: 0,
            },
            notary_session_id: None,
            attestation: None,
            secrets: None,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), Arc::new(Mutex::new(session_info)));

        session_id
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<Mutex<SessionInfo>>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session status
    pub async fn update_status(
        &self,
        session_id: &str,
        status: SessionStatus,
        stage: Option<String>,
        percentage: Option<u8>,
    ) -> Result<(), String> {
        if let Some(session) = self.get_session(session_id).await {
            let mut session_info = session.lock().await;
            session_info.status = status.clone();

            if let Some(stage) = stage {
                session_info.progress.stage = stage;
            }
            if let Some(percentage) = percentage {
                session_info.progress.percentage = percentage;
            }

            if status == SessionStatus::Completed || status == SessionStatus::Failed {
                session_info.completed_at = Some(Utc::now());
            }

            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Set session error
    pub async fn set_error(&self, session_id: &str, error: String) -> Result<(), String> {
        if let Some(session) = self.get_session(session_id).await {
            let mut session_info = session.lock().await;
            session_info.status = SessionStatus::Failed;
            session_info.error = Some(error);
            session_info.completed_at = Some(Utc::now());
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Update notary session ID
    pub async fn update_notary_session_id(
        &self,
        session_id: &str,
        notary_session_id: String,
    ) -> Result<(), String> {
        if let Some(session) = self.get_session(session_id).await {
            let mut session_info = session.lock().await;
            session_info.notary_session_id = Some(notary_session_id);
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Set attestation data for a session
    pub async fn set_attestation(
        &self,
        session_id: &str,
        attestation: Vec<u8>,
        secrets: Vec<u8>,
    ) -> Result<(), String> {
        if let Some(session) = self.get_session(session_id).await {
            let mut session_info = session.lock().await;
            session_info.attestation = Some(attestation);
            session_info.secrets = Some(secrets);
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Get attestation data for a session
    pub async fn get_attestation(&self, session_id: &str) -> Result<Option<Vec<u8>>, String> {
        if let Some(session) = self.get_session(session_id).await {
            let session_info = session.lock().await;
            Ok(session_info.attestation.clone())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Get secrets data for a session  
    pub async fn get_secrets(&self, session_id: &str) -> Result<Option<Vec<u8>>, String> {
        if let Some(session) = self.get_session(session_id).await {
            let session_info = session.lock().await;
            Ok(session_info.secrets.clone())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// Remove a session from the store
    pub async fn remove_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            Ok(())
        } else {
            Err(format!("Session {} not found", session_id))
        }
    }

    /// List all sessions
    pub async fn list_sessions(&self) -> Vec<SessionSummary> {
        let sessions = self.sessions.read().await;
        let mut summaries = Vec::new();

        for session in sessions.values() {
            let session_info = session.lock().await;
            summaries.push(SessionSummary {
                session_id: session_info.id.clone(),
                status: session_info.status.clone(),
                target_api: session_info.request.target_api.clone(),
                created_at: session_info.created_at,
                completed_at: session_info.completed_at,
            });
        }

        // Sort by creation time (newest first)
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries
    }

    /// Clean up old completed sessions (older than 1 hour)
    pub async fn cleanup_old_sessions(&self) {
        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let mut sessions = self.sessions.write().await;

        sessions.retain(|_, session| {
            // Try to lock the session, if not possible keep it for now
            if let Ok(session_info) = session.try_lock() {
                // Keep sessions that are still active or completed recently
                match session_info.status {
                    SessionStatus::Completed | SessionStatus::Failed => session_info
                        .completed_at
                        .map_or(true, |completed| completed > cutoff),
                    _ => true, // Keep active sessions
                }
            } else {
                true // Keep if can't lock (session might be in use)
            }
        });
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
