//! Jev backend: TypeSafe's System One API (`POST /v1/systemone`).
//!
//! Wire-compatible with the docs at docs.typesafe.ai: `state` + typed
//! `questions` in, one typed `answer` per question out. Choice and Score
//! answers carry calibrated `confidence`; Noul answers carry their
//! probability directly. Requires a waitlist/early-access API key.

use super::BackendConfig;
use crate::alert::Alert;
use crate::questions;
use crate::types::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// One answer from the API, tagged by question type.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum JevAnswer {
    #[serde(rename = "choice")]
    Choice {
        choice: String,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
    #[serde(rename = "score")]
    Score {
        score: f64,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
    #[serde(rename = "noul")]
    Noul { noul: f64 },
}

#[derive(Debug, Deserialize)]
struct JevResponse {
    #[serde(default)]
    answers: BTreeMap<String, JevAnswer>,
}

/// Jev-backed decision transport.
#[derive(Debug)]
pub struct JevBackend {
    client: reqwest::Client,
    url: String,
    api_key: String,
    model: String,
    questions: Value,
}

/// 429/529 are explicitly retryable per the TypeSafe API docs; retry with
/// a short exponential backoff.
const MAX_ATTEMPTS: usize = 3;

impl JevBackend {
    pub fn new(cfg: &BackendConfig) -> Result<Self, String> {
        let api_key = cfg
            .api_key
            .clone()
            .ok_or("backend 'jev' requires an API key (--api-key or TYPESAFE_API_KEY)")?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            client,
            url: cfg.typesafe_url.clone(),
            // Model resolution happens in the CLI; "jev-latest" is the default there.
            model: cfg.model.clone(),
            api_key,
            questions: questions::typesafe_questions(),
        })
    }

    pub async fn assess(&self, alert: &Alert) -> Result<RawAnswers, String> {
        let body = json!({
            "state": alert.raw,
            "model": self.model,
            "questions": self.questions,
        });

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    500 * (1 << attempt) as u64,
                ))
                .await;
            }
            match self.attempt(&body).await {
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

    /// Returns `(retryable, error)`.
    async fn attempt(&self, body: &Value) -> Result<RawAnswers, (bool, String)> {
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| (true, format!("typesafe request failed: {e}")))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| (true, format!("reading typesafe response: {e}")))?;

        if !status.is_success() {
            let retryable = status.as_u16() == 429 || status.as_u16() == 529;
            return Err((
                retryable,
                format!(
                    "typesafe HTTP {status}: {}",
                    crate::util::truncate(&text, 300)
                ),
            ));
        }

        let parsed: JevResponse = serde_json::from_str(&text)
            .map_err(|e| (false, format!("typesafe response parse: {e}")))?;

        let take = |name: &str| -> Result<JevAnswer, String> {
            parsed
                .answers
                .get(name)
                .map(|a| match a {
                    JevAnswer::Choice {
                        choice,
                        probabilities,
                        confidence,
                    } => JevAnswer::Choice {
                        choice: choice.clone(),
                        probabilities: probabilities.clone(),
                        confidence: *confidence,
                    },
                    JevAnswer::Score {
                        score,
                        probabilities,
                        confidence,
                    } => JevAnswer::Score {
                        score: *score,
                        probabilities: probabilities.clone(),
                        confidence: *confidence,
                    },
                    JevAnswer::Noul { noul } => JevAnswer::Noul { noul: *noul },
                })
                .ok_or_else(|| format!("typesafe response missing answer '{name}'"))
        };

        let disposition = match take("disposition").map_err(|e| (false, e))? {
            JevAnswer::Choice {
                choice,
                probabilities,
                confidence,
            } => ChoiceAnswer {
                choice,
                probabilities,
                confidence,
            },
            _ => return Err((false, "disposition answer had wrong type".into())),
        };
        let severity = match take("severity").map_err(|e| (false, e))? {
            JevAnswer::Score {
                score,
                probabilities,
                confidence,
            } => ScoreAnswer {
                score,
                probabilities,
                confidence,
            },
            _ => return Err((false, "severity answer had wrong type".into())),
        };
        let fp = match take("false_positive_probability").map_err(|e| (false, e))? {
            JevAnswer::Noul { noul } => NoulAnswer { noul },
            _ => {
                return Err((
                    false,
                    "false_positive_probability answer had wrong type".into(),
                ));
            }
        };
        let esc = match take("requires_escalation").map_err(|e| (false, e))? {
            JevAnswer::Noul { noul } => NoulAnswer { noul },
            _ => return Err((false, "requires_escalation answer had wrong type".into())),
        };
        let attack = match take("attack_class").map_err(|e| (false, e))? {
            JevAnswer::Choice {
                choice,
                probabilities,
                confidence,
            } => ChoiceAnswer {
                choice,
                probabilities,
                confidence,
            },
            _ => return Err((false, "attack_class answer had wrong type".into())),
        };

        Ok(RawAnswers {
            disposition: Some(disposition),
            severity: Some(severity),
            false_positive_probability: Some(fp),
            requires_escalation: Some(esc),
            attack_class: Some(attack),
        })
    }
}

/// Doctor support: validate config and run a live round trip against TypeSafe.
pub async fn doctor(cfg: &BackendConfig) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    lines.push(format!("typesafe endpoint: {}", cfg.typesafe_url));

    let backend = JevBackend::new(cfg)?;
    lines.push(format!("model: {}", backend.model));

    let probe = crate::alert::parse_alert(
        r#"{"id":"doctor","rule":"doctor probe","severity":"low","host":"localhost"}"#,
        0,
    )
    .expect("static probe alert is valid");

    let started = std::time::Instant::now();
    let raw = backend
        .assess(&probe)
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
