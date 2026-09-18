//! Backends: the transport that turns an `Alert` into `RawAnswers`.
//!
//! Three implementations, one contract:
//! - `ollama`: any LLM served by Ollama, constrained to our JSON schema
//! - `jev`:    TypeSafe's System One API — typed primitives, calibrated confidence
//! - `mock`:   deterministic, offline; used by tests and dry runs

pub mod jev;
pub mod mock;
pub mod openai;

use crate::alert::Alert;
use crate::context::TriageContext;
use crate::types::RawAnswers;

/// Which backend to run. `jev` is the intended path; `openai` is the
/// fallback for any OpenAI-compatible server; `mock` is for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Mock,
    OpenAi,
    Jev,
}

impl BackendKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "openai" | "openai-compatible" | "ollama" => Ok(Self::OpenAi),
            "jev" | "typesafe" => Ok(Self::Jev),
            other => Err(format!(
                "unknown backend '{other}' (expected: jev | openai | mock)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::OpenAi => "openai",
            Self::Jev => "jev",
        }
    }
}

/// Backend configuration, gathered from CLI flags.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub kind: BackendKind,
    pub model: String,
    /// Base URL of the OpenAI-compatible API (without `/chat/completions`).
    pub openai_url: String,
    pub typesafe_url: String,
    /// The key for whichever backend is in play; resolved per-kind in main.rs.
    pub api_key: Option<String>,
    pub timeout_secs: u64,
}

/// The enum-dispatch over backends. Keeping it concrete avoids async-trait
/// machinery and keeps the call path obvious.
#[derive(Debug)]
pub enum Backends {
    Mock(mock::MockBackend),
    OpenAi(openai::OpenAiBackend),
    Jev(jev::JevBackend),
}

impl Backends {
    pub fn from_config(cfg: &BackendConfig) -> Result<Self, String> {
        match cfg.kind {
            BackendKind::Mock => Ok(Self::Mock(mock::MockBackend)),
            BackendKind::OpenAi => Ok(Self::OpenAi(openai::OpenAiBackend::new(cfg)?)),
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
            Self::OpenAi(b) => b.assess(alert, context).await,
            Self::Jev(b) => b.assess(alert, context).await,
        }
    }
}
