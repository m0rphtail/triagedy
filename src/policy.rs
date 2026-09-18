//! Policy: turn a `Decision` into an `Action`, in plain code.
//!
//! This is the point of the whole exercise — the model produces calibrated
//! judgments; the routing logic is ordinary, inspectable, testable code.

use crate::decision::Decision;
use serde::{Deserialize, Serialize};

/// What the pipeline should do with the alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Close,
    Investigate,
    Escalate,
    Contain,
}

/// The full assessment attached to an alert's output record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub action: Action,
    pub review_required: bool,
    pub notes: Vec<String>,
}

/// Route a decision to an action. Precedence is explicit and in code:
///
/// 1. The model's disposition leads.
/// 2. A `close` verdict must survive a false-positive-probability gate that
///    gets stricter as severity rises.
/// 3. `investigate` can be upgraded to `escalate` when escalation and
///    severity probabilities are both high.
pub fn assess(d: &Decision) -> Assessment {
    let mut notes = Vec::new();

    let mut action = match d.disposition.as_str() {
        "escalate" => Action::Escalate,
        "contain" => Action::Contain,
        "close" => {
            let threshold = if d.severity >= 2.0 { 0.7 } else { 0.5 };
            if d.false_positive_probability >= threshold {
                Action::Close
            } else {
                notes.push(format!(
                    "close held back: false-positive probability {:.2} below {:.2} at severity {:.2}",
                    d.false_positive_probability, threshold, d.severity
                ));
                Action::Investigate
            }
        }
        _ => Action::Investigate,
    };

    if action == Action::Investigate && d.requires_escalation >= 0.9 && d.severity >= 2.0 {
        notes.push(format!(
            "upgraded to escalate: requires_escalation {:.2}, severity {:.2}",
            d.requires_escalation, d.severity
        ));
        action = Action::Escalate;
    }

    // A restatement of already-handled activity may be downgraded — but only
    // the least dangerous direction, and never when severity is high (a new
    // stage of the same incident is not a duplicate).
    if let Some(dup) = d.duplicate_probability
        && dup >= 0.8
    {
        if action == Action::Escalate && d.severity < 2.0 {
            notes.push(format!(
                "downgraded escalate→investigate: duplicate of recent activity (p={dup:.2}), severity {:.2}",
                d.severity
            ));
            action = Action::Investigate;
        } else {
            notes.push(format!(
                "possible duplicate of recent activity (p={dup:.2})"
            ));
        }
    }

    let mut review_required = false;
    if d.disposition_confidence < 0.6 {
        review_required = true;
        notes.push(format!(
            "low disposition confidence ({:.2})",
            d.disposition_confidence
        ));
    }
    if d.severity_confidence < 0.6 {
        review_required = true;
        notes.push(format!(
            "low severity confidence ({:.2})",
            d.severity_confidence
        ));
    }

    Assessment {
        action,
        review_required,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(disposition: &str, severity: f64, fp: f64, esc: f64) -> Decision {
        Decision {
            disposition: disposition.into(),
            disposition_confidence: 0.9,
            severity,
            severity_confidence: 0.9,
            false_positive_probability: fp,
            requires_escalation: esc,
            attack_class: "none".into(),
            attack_class_confidence: 0.9,
            duplicate_probability: None,
        }
    }

    #[test]
    fn disposition_leads() {
        assert_eq!(
            assess(&decision("escalate", 2.0, 0.1, 0.9)).action,
            Action::Escalate
        );
        assert_eq!(
            assess(&decision("contain", 3.0, 0.0, 1.0)).action,
            Action::Contain
        );
        assert_eq!(
            assess(&decision("investigate", 1.0, 0.2, 0.3)).action,
            Action::Investigate
        );
    }

    #[test]
    fn close_requires_fp_gate() {
        assert_eq!(
            assess(&decision("close", 0.5, 0.8, 0.1)).action,
            Action::Close
        );
        assert_eq!(
            assess(&decision("close", 0.5, 0.3, 0.1)).action,
            Action::Investigate
        );
    }

    #[test]
    fn close_gate_is_stricter_at_high_severity() {
        // severity 2.0 raises the threshold to 0.7: 0.6 is not enough anymore.
        assert_eq!(
            assess(&decision("close", 2.2, 0.6, 0.1)).action,
            Action::Investigate
        );
        assert_eq!(
            assess(&decision("close", 2.2, 0.75, 0.1)).action,
            Action::Close
        );
    }

    #[test]
    fn investigate_upgrades_to_escalate() {
        assert_eq!(
            assess(&decision("investigate", 2.5, 0.05, 0.95)).action,
            Action::Escalate
        );
        // needs both conditions
        assert_eq!(
            assess(&decision("investigate", 1.0, 0.05, 0.95)).action,
            Action::Investigate
        );
        assert_eq!(
            assess(&decision("investigate", 2.5, 0.05, 0.5)).action,
            Action::Investigate
        );
    }

    #[test]
    fn low_confidence_flags_review() {
        let mut d = decision("close", 0.5, 0.9, 0.0);
        d.disposition_confidence = 0.4;
        let a = assess(&d);
        assert!(a.review_required);
        assert_eq!(a.action, Action::Close);

        let d = decision("escalate", 2.0, 0.1, 0.9);
        assert!(!assess(&d).review_required);
    }

    #[test]
    fn duplicate_downgrades_low_severity_escalation() {
        let mut d = decision("escalate", 1.2, 0.1, 0.9);
        d.duplicate_probability = Some(0.9);
        let a = assess(&d);
        assert_eq!(a.action, Action::Investigate);
        assert!(
            a.notes.iter().any(|n| n.contains("duplicate")),
            "notes: {:?}",
            a.notes
        );
    }

    #[test]
    fn duplicate_never_downgrades_high_severity() {
        let mut d = decision("escalate", 2.5, 0.1, 0.9);
        d.duplicate_probability = Some(0.95);
        let a = assess(&d);
        assert_eq!(a.action, Action::Escalate);
        assert!(a.notes.iter().any(|n| n.contains("duplicate")));
    }

    #[test]
    fn duplicate_notes_but_does_not_change_other_actions() {
        let mut d = decision("close", 0.5, 0.9, 0.0);
        d.duplicate_probability = Some(0.85);
        let a = assess(&d);
        assert_eq!(a.action, Action::Close);
        assert!(a.notes.iter().any(|n| n.contains("duplicate")));
    }

    #[test]
    fn low_duplicate_probability_is_ignored() {
        let mut d = decision("escalate", 1.2, 0.1, 0.9);
        d.duplicate_probability = Some(0.4);
        assert_eq!(assess(&d).action, Action::Escalate);
        assert!(!assess(&d).notes.iter().any(|n| n.contains("duplicate")));
    }
}
