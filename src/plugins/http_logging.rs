use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::PluginHttpClient;
use super::{Plugin, TransactionSummary};

struct BatchConfig {
    endpoint_url: String,
    authorization_header: Option<String>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
}

pub struct HttpLogging {
    sender: mpsc::Sender<TransactionSummary>,
    endpoint_hostname: Option<String>,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let endpoint_url = config["endpoint_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "http_logging: 'endpoint_url' is required — logs will have nowhere to send"
                    .to_string()
            })?
            .to_string();

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

        let batch_config = BatchConfig {
            endpoint_url,
            authorization_header: config["authorization_header"]
                .as_str()
                .map(|s| s.to_string()),
            http_client,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(3) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
        };

        let endpoint_hostname = Url::parse(&batch_config.endpoint_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, batch_config));

        Ok(Self {
            sender,
            endpoint_hostname,
        })
    }
}

#[async_trait]
impl Plugin for HttpLogging {
    fn name(&self) -> &str {
        "http_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::HTTP_LOGGING
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self.sender.try_send(summary.clone()).is_err() {
            warn!("HTTP logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

async fn flush_loop(mut receiver: mpsc::Receiver<TransactionSummary>, cfg: BatchConfig) {
    if cfg.endpoint_url.is_empty() {
        // Drain the channel without sending anything.
        while receiver.recv().await.is_some() {}
        return;
    }

    let mut buffer: Vec<TransactionSummary> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    // The first tick completes immediately — consume it so the first real
    // flush waits for one full interval.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(summary) => {
                        buffer.push(summary);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, batch).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    send_batch(&cfg, batch).await;
                }
            }
        }
    }
}

async fn send_batch(cfg: &BatchConfig, batch: Vec<TransactionSummary>) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    for attempt in 1..=total_attempts {
        let mut req = cfg.http_client.get().post(&cfg.endpoint_url).json(&batch);
        if let Some(auth) = &cfg.authorization_header {
            req = req.header("Authorization", auth);
        }
        match req.send().await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                warn!(
                    "HTTP logging batch failed with status {} (attempt {}/{})",
                    response.status(),
                    attempt,
                    total_attempts,
                );
            }
            Err(e) => {
                warn!(
                    "HTTP logging batch failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "HTTP logging batch discarded after {} attempts ({} entries lost)",
        total_attempts, entry_count,
    );
    // `batch` is dropped here, freeing memory.
}
