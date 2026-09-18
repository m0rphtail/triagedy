//! The typed decision: what every backend's raw answers collapse into,
//! validated against the defined option sets and value ranges.

use crate::types::{
    ATTACK_CLASSES, ChoiceAnswer, DISPOSITIONS, NoulAnswer, RawAnswers, ScoreAnswer,
};
use serde::{Deserialize, Serialize};

/// A validated, typed triage decision. This is the value that code —
/// or a downstream pipeline — can branch on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub disposition: String,
    pub disposition_confidence: f64,
    pub severity: f64,
    pub severity_confidence: f64,
    pub false_positive_probability: f64,
    pub requires_escalation: f64,
    pub attack_class: String,
    pub attack_class_confidence: f64,
}

impl Decision {
    /// Validate raw answers and fold them into a `Decision`.
    /// Rejects answers outside the defined option sets or value ranges —
    /// a bad backend output is an error, never a silent default.
    pub fn from_answers(a: &RawAnswers) -> Result<Self, String> {
        let disposition: &ChoiceAnswer = a
            .disposition
            .as_ref()
            .ok_or("missing answer: disposition")?;
        if !DISPOSITIONS.iter().any(|d| *d == disposition.choice) {
            return Err(format!(
                "invalid disposition option: {}",
                disposition.choice
            ));
        }

        let severity: &ScoreAnswer = a.severity.as_ref().ok_or("missing answer: severity")?;
        if !severity.score.is_finite() || !(0.0..=3.0).contains(&severity.score) {
            return Err(format!("severity out of range 0-3: {}", severity.score));
        }

        let fp: &NoulAnswer = a
            .false_positive_probability
            .as_ref()
            .ok_or("missing answer: false_positive_probability")?;
        let esc: &NoulAnswer = a
            .requires_escalation
            .as_ref()
            .ok_or("missing answer: requires_escalation")?;
        for (name, v) in [
            ("false_positive_probability", fp.noul),
            ("requires_escalation", esc.noul),
        ] {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                return Err(format!("{name} out of range 0-1: {v}"));
            }
        }

        let attack = a
            .attack_class
            .as_ref()
            .ok_or("missing answer: attack_class")?;
        if !ATTACK_CLASSES.iter().any(|c| *c == attack.choice) {
            return Err(format!("invalid attack_class option: {}", attack.choice));
        }

        Ok(Self {
            disposition: disposition.choice.clone(),
            disposition_confidence: disposition.confidence,
            severity: severity.score,
            severity_confidence: severity.confidence,
            false_positive_probability: fp.noul,
            requires_escalation: esc.noul,
            attack_class: attack.choice.clone(),
            attack_class_confidence: attack.confidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn raw_valid() -> RawAnswers {
        let mut probs = BTreeMap::new();
        probs.insert("close".to_string(), 0.05);
        probs.insert("escalate".to_string(), 0.85);
        probs.insert("contain".to_string(), 0.05);
        probs.insert("investigate".to_string(), 0.05);
        RawAnswers {
            disposition: Some(ChoiceAnswer {
                choice: "escalate".into(),
                probabilities: probs,
                confidence: 0.85,
            }),
            severity: Some(ScoreAnswer {
                score: 2.1,
                probabilities: BTreeMap::new(),
                confidence: 0.8,
            }),
            false_positive_probability: Some(NoulAnswer { noul: 0.12 }),
            requires_escalation: Some(NoulAnswer { noul: 0.91 }),
            attack_class: Some(ChoiceAnswer {
                choice: "execution".into(),
                probabilities: BTreeMap::new(),
                confidence: 0.7,
            }),
            duplicate_of_recent: None,
        }
    }

    #[test]
    fn folds_valid_answers() {
        let d = Decision::from_answers(&raw_valid()).unwrap();
        assert_eq!(d.disposition, "escalate");
        assert_eq!(d.severity, 2.1);
        assert_eq!(d.attack_class, "execution");
    }

    #[test]
    fn rejects_unknown_option() {
        let mut raw = raw_valid();
        raw.disposition.as_mut().unwrap().choice = "panic".into();
        assert!(Decision::from_answers(&raw).is_err());
    }

    #[test]
    fn rejects_out_of_range_values() {
        let mut raw = raw_valid();
        raw.severity.as_mut().unwrap().score = 4.2;
        assert!(Decision::from_answers(&raw).is_err());

        let mut raw = raw_valid();
        raw.requires_escalation.as_mut().unwrap().noul = 1.5;
        assert!(Decision::from_answers(&raw).is_err());
    }

    #[test]
    fn rejects_missing_answers() {
        let mut raw = raw_valid();
        raw.attack_class = None;
        assert!(Decision::from_answers(&raw).is_err());
    }
}
