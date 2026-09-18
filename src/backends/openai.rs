//! OpenAI-compatible backend: any server that speaks
//! `POST {base}/chat/completions` — Ollama's `/v1`, OpenRouter, vLLM,
//! LM Studio, llama.cpp, Groq, Together, and friends.
//!
//! This is the *fallback* path; `jev` is the intended one. Confidence values
//! here are the model's self-report — uncalibrated. Jev returns calibrated
//! probabilities.

use super::BackendConfig;
use crate::alert::Alert;
use crate::context::TriageContext;
use crate::questions;
use crate::types::*;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

/// The eight fields we ask for (nine with context).
#[derive(Debug, Deserialize)]
struct ChatDecision {
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

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    #[serde(default)]
    message: ChatMessage,
}

#[derive(Debug, Default, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    content: Option<String>,
    /// Some servers surface reasoning traces here instead of `content`.
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
}

/// Response-format ladder, strictest first. Servers reject different rungs,
/// so the first request probes and the working rung is cached per run.
pub const FORMAT_JSON_SCHEMA: u8 = 0;
pub const FORMAT_JSON_OBJECT: u8 = 1;
pub const FORMAT_NONE: u8 = 2;

/// Enough for two rung steps plus a parse retry.
const MAX_ATTEMPTS: usize = 5;

#[derive(Debug)]
pub struct OpenAiBackend {
    client: reqwest::Client,
    url: String,
    api_key: Option<String>,
    model: String,
    format_rung: AtomicU8,
}

impl OpenAiBackend {
    pub fn new(cfg: &BackendConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            client,
            url: format!("{}/chat/completions", cfg.openai_url.trim_end_matches('/')),
            api_key: cfg.api_key.clone(),
            model: cfg.model.clone(),
            format_rung: AtomicU8::new(FORMAT_JSON_SCHEMA),
        })
    }

    pub async fn assess(
        &self,
        alert: &Alert,
        context: Option<&TriageContext>,
    ) -> Result<RawAnswers, String> {
        let context = context.filter(|c| !c.is_empty());
        let prompt = questions::chat_prompt(alert, context);
        let with_context = context.is_some();

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            match self.attempt(&prompt, with_context).await {
                Ok(raw) => return Ok(raw),
                Err((retryable, e)) => {
                    last_err = e;
                    if !retryable {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Returns `(retryable, error)`. A 4xx that names `response_format` is a
    /// ladder step: advance the cached rung and retry immediately.
    async fn attempt(
        &self,
        prompt: &str,
        with_context: bool,
    ) -> Result<RawAnswers, (bool, String)> {
        let rung = self.format_rung.load(Ordering::Relaxed);

        let mut body = json!({
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a SOC triage analyst. Respond with a single JSON object and nothing else."
                },
                { "role": "user", "content": prompt }
            ],
            "temperature": 0.0,
            "stream": false,
        });
        match rung {
            FORMAT_JSON_SCHEMA => {
                body["response_format"] = json!({
                    "type": "json_schema",
                    "json_schema": {
                        "name": "triage_decision",
                        "strict": true,
                        "schema": questions::chat_schema(with_context),
                    }
                });
            }
            FORMAT_JSON_OBJECT => {
                body["response_format"] = json!({ "type": "json_object" });
            }
            _ => {}
        }

        let mut req = self.client.post(&self.url).json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| (true, format!("openai request failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| (true, format!("reading openai response: {e}")))?;

        if !status.is_success() {
            let lower = text.to_ascii_lowercase();
            let names_format = lower.contains("response_format") || lower.contains("json_schema");
            if (400..500).contains(&status.as_u16()) && names_format && rung < FORMAT_NONE {
                self.format_rung.store(rung + 1, Ordering::Relaxed);
                return Err((
                    true,
                    format!(
                        "openai HTTP {status}: server rejected response_format rung {rung}, stepping down"
                    ),
                ));
            }
            let retryable = status.as_u16() == 429 || status.as_u16() >= 500;
            return Err((
                retryable,
                format!(
                    "openai HTTP {status}: {}",
                    crate::util::truncate(&text, 300)
                ),
            ));
        }

        let parsed: ChatResponse = serde_json::from_str(&text)
            .map_err(|e| (false, format!("openai response envelope parse: {e}")))?;
        let message = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message)
            .unwrap_or_default();
        let content = message.content.unwrap_or_default();

        if content.trim().is_empty() {
            if message.reasoning_content.is_some() || message.reasoning.is_some() {
                return Err((
                    false,
                    "model returned only reasoning text (empty content) — disable thinking \
                     on the model, or use a non-thinking model for triage"
                        .to_string(),
                ));
            }
            return Err((false, "model returned an empty response".to_string()));
        }

        let json_text = extract_json(&content).ok_or_else(|| {
            (
                false,
                format!(
                    "no JSON object in model output: {}",
                    crate::util::truncate(&content, 200)
                ),
            )
        })?;
        let decision: ChatDecision = serde_json::from_str(&json_text).map_err(|e| {
            (
                false,
                format!(
                    "model output not valid decision JSON: {e}: {}",
                    crate::util::truncate(&json_text, 200)
                ),
            )
        })?;

        Ok(RawAnswers {
            disposition: Some(ChoiceAnswer {
                choice: decision.disposition,
                probabilities: BTreeMap::new(),
                confidence: decision.disposition_confidence,
            }),
            severity: Some(ScoreAnswer {
                score: decision.severity,
                probabilities: BTreeMap::new(),
                confidence: decision.severity_confidence,
            }),
            false_positive_probability: Some(NoulAnswer {
                noul: decision.false_positive_probability,
            }),
            requires_escalation: Some(NoulAnswer {
                noul: decision.requires_escalation,
            }),
            attack_class: Some(ChoiceAnswer {
                choice: decision.attack_class,
                probabilities: BTreeMap::new(),
                confidence: decision.attack_class_confidence,
            }),
            duplicate_of_recent: decision.duplicate_of_recent.map(|noul| NoulAnswer { noul }),
        })
    }
}

/// Pull the first JSON object out of model output: raw JSON, ```json fences,
/// or prose that wraps a single object. Cheap insurance — the format ladder
/// gets most servers to emit clean JSON, and this catches the ones that don't.
fn extract_json(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Some(trimmed.to_string());
    }
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    (end > start).then(|| trimmed[start..=end].to_string())
}

/// Doctor: reachability, model presence, then a live round trip.
pub async fn doctor(cfg: &BackendConfig) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let base = cfg.openai_url.trim_end_matches('/').to_string();
    lines.push(format!("openai-compatible endpoint: {base}"));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut req = client.get(format!("{base}/models"));
    if let Some(key) = &cfg.api_key {
        req = req.bearer_auth(key);
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await.unwrap_or_default();
            let model_seen = text.contains(&cfg.model);
            lines.push(format!(
                "reached {base}/models{}",
                if model_seen {
                    format!(" — '{}' present", cfg.model)
                } else {
                    format!(" — '{}' not listed (may still work)", cfg.model)
                }
            ));
        }
        Ok(resp) => {
            return Err(format!(
                "{base}/models returned HTTP {} — is this an OpenAI-compatible server?",
                resp.status()
            ));
        }
        Err(e) => return Err(format!("cannot reach {base}: {e}")),
    }

    let probe = crate::alert::parse_alert(
        r#"{"id":"doctor","rule":"doctor probe","severity":"low","host":"localhost"}"#,
        0,
    )
    .expect("static probe alert is valid");
    let backend = OpenAiBackend::new(cfg)?;
    let started = std::time::Instant::now();
    let raw = backend
        .assess(&probe, None)
        .await
        .map_err(|e| format!("decision round-trip failed — {e}"))?;
    let decision = crate::decision::Decision::from_answers(&raw)
        .map_err(|e| format!("round-trip output invalid — {e}"))?;
    lines.push(format!(
        "decision round-trip OK in {} ms (format rung {}): disposition={} ({:.2}), severity={:.2}, fp={:.2}, escalate={:.2}, attack_class={}",
        started.elapsed().as_millis(),
        backend.format_rung.load(Ordering::Relaxed),
        decision.disposition,
        decision.disposition_confidence,
        decision.severity,
        decision.false_positive_probability,
        decision.requires_escalation,
        decision.attack_class,
    ));
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_handles_the_three_real_shapes() {
        assert_eq!(extract_json(r#"{"a":1}"#).as_deref(), Some(r#"{"a":1}"#));
        assert_eq!(
            extract_json("```json\n{\"a\":1}\n```").as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert_eq!(
            extract_json("Sure! Here you go:\n{\"a\":1}\nHope that helps.").as_deref(),
            Some(r#"{"a":1}"#)
        );
        assert_eq!(extract_json("no object here"), None);
        assert_eq!(extract_json("}{"), None);
    }

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg_for(server: &MockServer) -> BackendConfig {
        BackendConfig {
            kind: crate::backends::BackendKind::OpenAi,
            model: "test-model".to_string(),
            openai_url: server.uri(),
            typesafe_url: "http://unused".to_string(),
            api_key: None,
            timeout_secs: 10,
        }
    }

    fn decision_json() -> String {
        serde_json::json!({
            "disposition": "investigate",
            "disposition_confidence": 0.8,
            "severity": 2.0,
            "severity_confidence": 0.9,
            "false_positive_probability": 0.2,
            "requires_escalation": 0.7,
            "attack_class": "execution",
            "attack_class_confidence": 0.85
        })
        .to_string()
    }

    fn alert() -> Alert {
        crate::alert::parse_alert(r#"{"id":"a","rule":"r"}"#, 0).unwrap()
    }

    #[tokio::test]
    async fn steps_down_when_json_schema_is_rejected() {
        let server = MockServer::start().await;
        // First rung rejected, second accepted.
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string("unsupported parameter: response_format"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": decision_json() } }]
            })))
            .mount(&server)
            .await;

        let backend = OpenAiBackend::new(&cfg_for(&server)).unwrap();
        let raw = backend.assess(&alert(), None).await.unwrap();
        assert_eq!(raw.disposition.unwrap().choice, "investigate");
        // The working rung is cached for the rest of the run.
        assert_eq!(
            backend.format_rung.load(Ordering::Relaxed),
            FORMAT_JSON_OBJECT
        );
    }

    #[tokio::test]
    async fn parses_fenced_json_from_content() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": {
                    "content": format!("```json\n{}\n```", decision_json())
                } }]
            })))
            .mount(&server)
            .await;

        let backend = OpenAiBackend::new(&cfg_for(&server)).unwrap();
        assert!(backend.assess(&alert(), None).await.is_ok());
    }

    #[tokio::test]
    async fn empty_content_with_reasoning_gets_a_clear_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": {
                    "content": "",
                    "reasoning_content": "let me think about this..."
                } }]
            })))
            .mount(&server)
            .await;

        let backend = OpenAiBackend::new(&cfg_for(&server)).unwrap();
        let err = backend.assess(&alert(), None).await.unwrap_err();
        assert!(err.contains("reasoning"), "err was: {err}");
    }

    #[tokio::test]
    async fn falls_all_the_way_to_no_format_when_the_server_rejects_both() {
        let server = MockServer::start().await;
        for _ in 0..2 {
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(
                    ResponseTemplate::new(400).set_body_string("response_format not supported"),
                )
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": decision_json() } }]
            })))
            .mount(&server)
            .await;

        let backend = OpenAiBackend::new(&cfg_for(&server)).unwrap();
        assert!(backend.assess(&alert(), None).await.is_ok());
        assert_eq!(backend.format_rung.load(Ordering::Relaxed), FORMAT_NONE);
    }

    #[tokio::test]
    async fn context_is_sent_in_the_prompt() {
        use crate::context::{ContextItem, TriageContext};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{ "message": { "content": serde_json::json!({
                    "disposition": "close",
                    "disposition_confidence": 0.9,
                    "severity": 0.5,
                    "severity_confidence": 0.8,
                    "false_positive_probability": 0.9,
                    "requires_escalation": 0.1,
                    "attack_class": "none",
                    "attack_class_confidence": 0.9,
                    "duplicate_of_recent": 0.85
                }).to_string() } }]
            })))
            .mount(&server)
            .await;

        let ctx = TriageContext {
            items: vec![ContextItem {
                id: "prev-1".into(),
                host: Some("WS-1".into()),
                rule: Some("earlier alert".into()),
                action: Some("escalate".into()),
                disposition: Some("escalate".into()),
                attack_class: Some("execution".into()),
                timestamp: Some("t0".into()),
            }],
        };
        let backend = OpenAiBackend::new(&cfg_for(&server)).unwrap();
        let raw = backend.assess(&alert(), Some(&ctx)).await.unwrap();
        assert_eq!(raw.duplicate_of_recent.unwrap().noul, 0.85);

        // The request body carried the context in the user message.
        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let user = body["messages"][1]["content"].as_str().unwrap();
        assert!(user.contains("prev-1"), "prompt was: {user}");
        assert!(user.contains("duplicate_of_recent"), "prompt was: {user}");
    }
}
