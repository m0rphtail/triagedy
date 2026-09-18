//! Shared types: the TypeSafe "System One" primitives (Choice / Score / Noul)
//! and the question definitions used by every backend.
//!
//! The `jev` backend speaks TypeSafe's wire format directly; `ollama` and
//! `mock` produce the same shapes so everything downstream is identical.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Disposition options for triage (Choice question).
pub const DISPOSITIONS: [&str; 4] = ["close", "escalate", "contain", "investigate"];

/// Attack phases for classification (Choice question), MITRE-flavoured.
pub const ATTACK_CLASSES: [&str; 6] = [
    "none",
    "execution",
    "credential_access",
    "persistence",
    "lateral_movement",
    "exfiltration",
];

/// Severity levels (Score question, 0-3, ordered).
pub const SEVERITY_LEVELS: [&str; 4] = [
    "Informational: benign, expected, or clearly explainable activity",
    "Low: suspicious but plausibly legitimate activity",
    "High: likely malicious activity requiring prompt action",
    "Critical: active compromise or destructive activity in progress",
];

/// A Choice answer: the winning option, the full probability distribution
/// across all options, and a confidence score derived from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChoiceAnswer {
    pub choice: String,
    pub probabilities: BTreeMap<String, f64>,
    pub confidence: f64,
}

/// A Score answer: the probability-weighted value across ordered levels,
/// the distribution across levels, and a confidence score derived from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreAnswer {
    pub score: f64,
    pub probabilities: BTreeMap<String, f64>,
    pub confidence: f64,
}

/// A Noul answer: the probability that the answer to a yes/no question is yes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoulAnswer {
    pub noul: f64,
}

/// The complete set of raw answers every backend must produce.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawAnswers {
    pub disposition: Option<ChoiceAnswer>,
    pub severity: Option<ScoreAnswer>,
    pub false_positive_probability: Option<NoulAnswer>,
    pub requires_escalation: Option<NoulAnswer>,
    pub attack_class: Option<ChoiceAnswer>,
    /// Only asked, and only answered, when a recent-activity context is in play.
    pub duplicate_of_recent: Option<NoulAnswer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_answers_defaults_duplicate_to_none() {
        let r = RawAnswers::default();
        assert!(r.duplicate_of_recent.is_none());
    }
}
