//! Ollama backend: any local model, constrained to our decision schema.
//!
//! This is the backend that works today, before Jev access lands. Confidence
//! values are the model's self-report — treat them as uncalibrated. Jev
//! provides calibrated probabilities; this exists so the pipeline is real now.

use super::BackendConfig;
use crate::alert::Alert;
use crate::context::TriageContext;
use crate::questions;
use crate::types::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Raw fields we ask the model for via the JSON schema.
#[derive(Debug, Deserialize)]
struct OllamaDecision {
    disposition: String,
    disposition_confidence: f64,
    severity: f64,
    severity_confidence: f64,
    false_positive_probability: f64,
    requires_escalation: f64,
    attack_class: String,
    attack_class_confidence: f64,
    #[serde(default)]
    duplicate_of_recent: Option<f64>,
}

/// Ollama-backed decision transport.
#[derive(Debug)]
pub struct OllamaBackend {
    client: reqwest::Client,
    url: String,
    model: String,
}

/// One retry: a local model occasionally drifts off-schema; the retry is
/// cheap compared to failing the alert.
const MAX_ATTEMPTS: usize = 2;

impl OllamaBackend {
    pub fn new(cfg: &BackendConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            client,
            url: format!("{}/api/generate", cfg.ollama_url.trim_end_matches('/')),
            model: cfg.model.clone(),
        })
    }

    pub async fn assess(
        &self,
        alert: &Alert,
        context: Option<&TriageContext>,
    ) -> Result<RawAnswers, String> {
        let prompt = questions::ollama_prompt(alert, context);
        let body = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            // Thinking-capable models route their whole reply into the
            // `thinking` field unless disabled, leaving `response` empty. Both
            // fields are handled below, so either kind of model works here.
            "format": questions::ollama_format_schema(context.is_some()),
            "think": false,
            "options": { "temperature": 0.0 },
        });

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            match self.attempt(&body).await {
                Ok(raw) => return Ok(raw),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn attempt(&self, body: &Value) -> Result<RawAnswers, String> {
        let resp = self
            .client
            .post(&self.url)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("ollama request failed: {e}"))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("reading ollama response: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "ollama HTTP {status}: {}",
                crate::util::truncate(&text, 300)
            ));
        }

        let envelope: Value =
            serde_json::from_str(&text).map_err(|e| format!("ollama envelope: {e}"))?;
        let response = envelope
            .get("response")
            .and_then(Value::as_str)
            .ok_or("ollama response missing 'response' field")?;
        if response.trim().is_empty() {
            let thinking = envelope
                .get("thinking")
                .and_then(Value::as_str)
                .unwrap_or("");
            return Err(if thinking.is_empty() {
                "ollama returned an empty response".to_string()
            } else {
                "ollama returned only thinking text (response empty); model needs think:false"
                    .to_string()
            });
        }

        let parsed: OllamaDecision = serde_json::from_str(response).map_err(|e| {
            format!(
                "model output not valid decision JSON: {e}: {}",
                crate::util::truncate(response, 200)
            )
        })?;

        Ok(RawAnswers {
            disposition: Some(ChoiceAnswer {
                choice: parsed.disposition,
                probabilities: BTreeMap::new(),
                confidence: parsed.disposition_confidence,
            }),
            severity: Some(ScoreAnswer {
                score: parsed.severity,
                probabilities: BTreeMap::new(),
                confidence: parsed.severity_confidence,
            }),
            false_positive_probability: Some(NoulAnswer {
                noul: parsed.false_positive_probability,
            }),
            requires_escalation: Some(NoulAnswer {
                noul: parsed.requires_escalation,
            }),
            attack_class: Some(ChoiceAnswer {
                choice: parsed.attack_class,
                probabilities: BTreeMap::new(),
                confidence: parsed.attack_class_confidence,
            }),
            duplicate_of_recent: parsed.duplicate_of_recent.map(|noul| NoulAnswer { noul }),
        })
    }
}

/// Doctor support: check reachability + model presence, then a live round trip.
pub async fn doctor(cfg: &BackendConfig) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let base = cfg.ollama_url.trim_end_matches('/').to_string();

    let version: Value = client
        .get(format!("{base}/api/version"))
        .send()
        .await
        .map_err(|e| format!("ollama unreachable at {base}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("ollama version parse: {e}"))?;
    let version = version
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    lines.push(format!("ollama reachable at {base} (version {version})"));

    let tags: Value = client
        .get(format!("{base}/api/tags"))
        .send()
        .await
        .map_err(|e| format!("ollama tags request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("ollama tags parse: {e}"))?;
    let models: Vec<String> = tags
        .get("models")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let model_ok = models
        .iter()
        .any(|m| m == &cfg.model || m.starts_with(&format!("{}:", cfg.model)));
    if !model_ok {
        return Err(format!(
            "model '{}' not found in ollama. Available: {}",
            cfg.model,
            models.join(", ")
        ));
    }
    lines.push(format!("model '{}' available", cfg.model));

    let probe = crate::alert::parse_alert(
        r#"{"id":"doctor","rule":"doctor probe","severity":"low","host":"localhost"}"#,
        0,
    )
    .expect("static probe alert is valid");
    let backend = OllamaBackend::new(cfg)?;
    let started = std::time::Instant::now();
    let raw = backend
        .assess(&probe, None)
        .await
        .map_err(|e| format!("decision round-trip failed — {e}"))?;
    let decision = crate::decision::Decision::from_answers(&raw)
        .map_err(|e| format!("round-trip output invalid — {e}"))?;
    lines.push(format!(
        "decision round-trip OK in {} ms: disposition={} ({:.2}), severity={:.2}, fp={:.2}, escalate={:.2}, attack_class={}",
        started.elapsed().as_millis(),
        decision.disposition,
        decision.disposition_confidence,
        decision.severity,
        decision.false_positive_probability,
        decision.requires_escalation,
        decision.attack_class,
    ));
    Ok(lines)
}
