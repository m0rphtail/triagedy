//! The triage questions themselves: the five decisions we ask of every alert.
//!
//! These are defined once and consumed two ways:
//! - as TypeSafe "System One" questions (Choice / Score / Noul) for the `jev` backend
//! - rendered into a plain-text prompt + JSON schema for the `openai` backend

use crate::alert::Alert;
use crate::context::TriageContext;
use crate::types::{ATTACK_CLASSES, DISPOSITIONS, SEVERITY_LEVELS};
use serde_json::{Value, json};

/// The TypeSafe questions map, sent verbatim as the `questions` field of a
/// `POST /v1/systemone` request.
pub fn typesafe_questions(with_context: bool) -> Value {
    let mut questions = json!({
        "disposition": {
            "type": "choice",
            "instructions": "Given this security alert, what is the correct triage disposition?",
            "criteria": {
                "close": "Benign or expected activity; no analyst action needed. Known-good tooling, scheduled tasks, sanctioned scanners, test traffic.",
                "investigate": "Suspicious enough to warrant an analyst look but not confirmable as benign or malicious. Unusual but explainable context.",
                "escalate": "Likely malicious activity that should go to incident response now. Malware execution, hands-on-keyboard activity, C2 beaconing, data staging.",
                "contain": "Active compromise requiring immediate isolation of host or account. Ransomware behavior, active exfiltration, interactive attacker session."
            }
        },
        "severity": {
            "type": "score",
            "instructions": "If this alert is a true positive, how severe is the activity?",
            "criteria": SEVERITY_LEVELS
        },
        "false_positive_probability": {
            "type": "noul",
            "instructions": "This alert is a false positive: benign or expected activity misclassified by the detection.",
            "criteria": {
                "true": "A strong benign explanation is present in the alert evidence: signed or known-good tool, sanctioned admin script, scanner, maintenance window.",
                "false": "No benign explanation, or the evidence supports maliciousness."
            }
        },
        "requires_escalation": {
            "type": "noul",
            "instructions": "This alert requires immediate escalation to the incident response team."
        },
        "attack_class": {
            "type": "choice",
            "instructions": "Which attacker technique category best matches this activity? Choose none if it does not indicate attacker behavior.",
            "criteria": {
                "none": "No attacker behavior indicated: benign, expected, or inconclusive activity.",
                "execution": "Running attacker code: script interpreters, unusual binaries, encoded or obfuscated commands.",
                "credential_access": "Stealing or guessing credentials: LSASS access, credential dumping, brute force, token theft.",
                "persistence": "Surviving reboot or maintaining access: services, scheduled tasks, autoruns, new accounts.",
                "lateral_movement": "Moving between hosts: SMB, RDP, WinRM, WMI, remote service creation.",
                "exfiltration": "Moving data out: large outbound transfers, archive staging, upload from server roles."
            }
        }
    });

    if with_context {
        questions["duplicate_of_recent"] = json!({
            "type": "noul",
            "instructions": "This alert is a restatement or continuation of activity already recorded in recent_activity: the same incident, or the same host, already actioned there.",
            "criteria": {
                "true": "recent_activity already shows this host or incident; this alert adds no new stage or evidence.",
                "false": "New activity, a new host, or a new stage of an incident not present in the context."
            }
        });
    }
    questions
}

/// The JSON schema the `openai` backend constrains generation to.
pub fn chat_schema(with_context: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": {
            "disposition": { "type": "string", "enum": DISPOSITIONS },
            "disposition_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "severity": { "type": "number", "minimum": 0.0, "maximum": 3.0 },
            "severity_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "false_positive_probability": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "requires_escalation": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "attack_class": { "type": "string", "enum": ATTACK_CLASSES },
            "attack_class_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
        },
        "required": [
            "disposition",
            "disposition_confidence",
            "severity",
            "severity_confidence",
            "false_positive_probability",
            "requires_escalation",
            "attack_class",
            "attack_class_confidence"
        ]
    });

    if with_context {
        schema["properties"]["duplicate_of_recent"] =
            json!({ "type": "number", "minimum": 0.0, "maximum": 1.0 });
        if let Some(required) = schema["required"].as_array_mut() {
            required.push(json!("duplicate_of_recent"));
        }
    }
    schema
}

/// How much of the alert JSON we feed to the model. Alerts are small;
/// this guards against pathological inputs.
const MAX_STATE_CHARS: usize = 8_000;

/// Render the prompt for an LLM asked to answer the same five questions.
pub fn chat_prompt(alert: &Alert, context: Option<&TriageContext>) -> String {
    let mut state = alert.raw.to_string();
    if state.chars().count() > MAX_STATE_CHARS {
        state = format!(
            "{}…(truncated)",
            state.chars().take(MAX_STATE_CHARS).collect::<String>()
        );
    }

    let mut q = String::new();
    q.push_str(
        "You are a SOC triage analyst. Read the security alert JSON below and answer the \
         triage questions with honest probabilities. Respond with one JSON object only.\n\n",
    );
    q.push_str(
        "Before judging: check every field of the alert as evidence. Change tickets, sanctioned \
         changes, asset registries, maintenance windows, and known-good tooling can legitimate \
         activity; encoded commands, temp paths, foreign IPs, and missing change records weigh \
         against it.\n\n",
    );
    if let Some(ctx) = context {
        q.push_str(
            "Recent activity already triaged (newest last) — use it to recognise repeats:\n",
        );
        for item in &ctx.items {
            q.push_str(&format!(
                "- id={} host={} rule={} action={} disposition={} at={}\n",
                item.id,
                item.host.as_deref().unwrap_or("-"),
                item.rule.as_deref().unwrap_or("-"),
                item.action.as_deref().unwrap_or("-"),
                item.disposition.as_deref().unwrap_or("-"),
                item.timestamp.as_deref().unwrap_or("-"),
            ));
        }
        q.push_str(
            "If this alert restates activity above (same incident, same host), raise \
             duplicate_of_recent. A NEW stage of an existing incident is NOT a duplicate.\n\n",
        );
    }
    q.push_str("Questions:\n");
    q.push_str(
        "1. disposition: one of close|escalate|contain|investigate. close=benign/expected, \
         investigate=suspicious but unconfirmed, escalate=likely malicious for IR now, \
         contain=active compromise needing isolation.\n",
    );
    q.push_str("2. disposition_confidence: 0.0-1.0, how certain you are of the disposition.\n");
    q.push_str(
        "3. severity: 0.0-3.0 if true positive. 0=informational, 1=low, 2=high, 3=critical.\n",
    );
    q.push_str("4. severity_confidence: 0.0-1.0.\n");
    q.push_str("5. false_positive_probability: 0.0-1.0, probability this is a false positive.\n");
    q.push_str("6. requires_escalation: 0.0-1.0, probability it needs immediate IR escalation.\n");
    q.push_str(
        "7. attack_class: one of none|execution|credential_access|persistence|lateral_movement|exfiltration.\n",
    );
    q.push_str("8. attack_class_confidence: 0.0-1.0.\n\n");
    if context.is_some() {
        q.push_str(
            "9. duplicate_of_recent: 0.0-1.0, probability this alert is already covered by the recent activity above.\n\n",
        );
    }
    q.push_str("Alert JSON:\n");
    q.push_str(&state);
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_set_gains_duplicate_only_with_context() {
        let without = typesafe_questions(false);
        let with = typesafe_questions(true);
        assert!(without.get("duplicate_of_recent").is_none());
        let obj = without.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "the no-context question map must stay exactly five questions"
        );
        for key in [
            "disposition",
            "severity",
            "false_positive_probability",
            "requires_escalation",
            "attack_class",
        ] {
            assert!(obj.contains_key(key), "missing {key}");
        }
        assert_eq!(with.as_object().unwrap().len(), 6);
        assert!(with.get("duplicate_of_recent").is_some());
    }

    #[test]
    fn chat_schema_gains_duplicate_only_with_context() {
        let without = chat_schema(false);
        assert!(without["properties"].get("duplicate_of_recent").is_none());
        let with = chat_schema(true);
        assert!(with["properties"]["duplicate_of_recent"]["type"] == "number");
        let required = with["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "duplicate_of_recent"));
    }
}
