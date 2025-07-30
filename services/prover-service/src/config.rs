use serde::{Deserialize, Serialize};

/// Main configuration for the prover service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub notary: NotaryConfig,
    pub session: SessionConfig,
    pub target_server: TargetServerConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub streaming: StreamingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryConfig {
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetServerConfig {
    pub default_host: String,
    pub default_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// Maximum number of retry attempts for streaming responses
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Delay between retry attempts in seconds
    #[serde(default = "default_retry_delay_secs")]
    pub retry_delay_secs: u64,
    /// Custom headers to check for streaming detection
    #[serde(default)]
    pub custom_streaming_headers: Vec<String>,
    /// Timeout for individual requests in seconds
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

impl Config {
    /// Load configuration from file
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path =
            std::env::var("PROVER_CONFIG").unwrap_or_else(|_| "prover.state.toml".to_string());

        let config_str = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config file '{}': {}", config_path, e))?;

        let config: Config = toml::from_str(&config_str)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;

        Ok(config)
    }

    /// Fetch and update notary configuration from the notary server
    pub async fn fetch_notary_config(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let protocol = if self.notary.tls_enabled {
            "https"
        } else {
            "http"
        };
        let url = format!(
            "{}://{}:{}/config",
            protocol, self.notary.host, self.notary.port
        );

        tracing::info!("Fetching notary config from: {}", url);

        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("Failed to fetch notary config from {}: {}", url, e))?;

        if !response.status().is_success() {
            return Err(format!("Notary server returned error: {}", response.status()).into());
        }

        let notary_config: NotaryConfigResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse notary config response: {}", e))?;

        // Update  configuration with the actual notary settings
        self.notary.host = notary_config.server.host;
        self.notary.port = notary_config.server.port;
        self.notary.tls_enabled = notary_config.tls.enabled;
        self.notary.timeout = notary_config.notarization.timeout;
        self.session.max_sent_data = notary_config.notarization.max_sent_data;
        self.session.max_recv_data = notary_config.notarization.max_recv_data;

        tracing::info!(
            "Updated notary config: {}:{} (TLS: {})",
            self.notary.host,
            self.notary.port,
            self.notary.tls_enabled
        );
        tracing::info!(
            "Updated session limits: sent={}, recv={}",
            self.session.max_sent_data,
            self.session.max_recv_data
        );

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NotaryConfigResponse {
    pub server: ServerConfigInfo,
    pub notarization: NotarizationConfigInfo,
    pub tls: TlsConfigInfo,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServerConfigInfo {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NotarizationConfigInfo {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub timeout: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TlsConfigInfo {
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                name: "prover-service".to_string(),
            },
            notary: NotaryConfig {
                host: "127.0.0.1".to_string(),
                port: 7047,
                tls_enabled: false,
                timeout: 1800,
            },
            session: SessionConfig {
                max_sent_data: 65536,
                max_recv_data: 20971520,
            },
            target_server: TargetServerConfig {
                default_host: "https://api.multiversx.com/stats".to_string(),
                default_port: 443,
            },
            logging: LoggingConfig {
                level: "DEBUG".to_string(),
            },
            streaming: StreamingConfig::default(),
        }
    }
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            retry_delay_secs: default_retry_delay_secs(),
            custom_streaming_headers: Vec::new(),
            request_timeout_secs: default_request_timeout_secs(),
        }
    }
}

fn default_max_retries() -> usize {
    10
}

fn default_retry_delay_secs() -> u64 {
    2
}

fn default_request_timeout_secs() -> u64 {
    30
}
