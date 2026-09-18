//! Backends: the transport that turns an `Alert` into `RawAnswers`.
//!
//! Three implementations, one contract:
//! - `ollama`: any LLM served by Ollama, constrained to our JSON schema
//! - `jev`:    TypeSafe's System One API — typed primitives, calibrated confidence
//! - `mock`:   deterministic, offline; used by tests and dry runs

pub mod jev;
pub mod mock;
pub mod ollama;

use crate::alert::Alert;
use crate::context::TriageContext;
use crate::types::RawAnswers;

/// Which backend to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Mock,
    Ollama,
    Jev,
}

impl BackendKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "ollama" => Ok(Self::Ollama),
            "jev" | "typesafe" => Ok(Self::Jev),
            other => Err(format!(
                "unknown backend '{other}' (expected: mock | ollama | jev)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Ollama => "ollama",
            Self::Jev => "jev",
        }
    }
}

/// Backend configuration, gathered from CLI flags.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub kind: BackendKind,
    pub model: String,
    pub ollama_url: String,
    pub typesafe_url: String,
    pub api_key: Option<String>,
    pub timeout_secs: u64,
}

/// The enum-dispatch over backends. Keeping it concrete avoids async-trait
/// machinery and keeps the call path obvious.
#[derive(Debug)]
pub enum Backends {
    Mock(mock::MockBackend),
    Ollama(ollama::OllamaBackend),
    Jev(jev::JevBackend),
}

impl Backends {
    pub fn from_config(cfg: &BackendConfig) -> Result<Self, String> {
        match cfg.kind {
            BackendKind::Mock => Ok(Self::Mock(mock::MockBackend)),
            BackendKind::Ollama => Ok(Self::Ollama(ollama::OllamaBackend::new(cfg)?)),
            BackendKind::Jev => Ok(Self::Jev(jev::JevBackend::new(cfg)?)),
        }
    }

    /// Ask the backend to assess one alert. `context`, when present, is the
    /// recent-activity window for this run.
    pub async fn assess(
        &self,
        alert: &Alert,
        context: Option<&TriageContext>,
    ) -> Result<RawAnswers, String> {
        match self {
            Self::Mock(b) => b.assess(alert, context).await,
            Self::Ollama(b) => b.assess(alert, context).await,
            Self::Jev(b) => b.assess(alert, context).await,
        }
    }
}
