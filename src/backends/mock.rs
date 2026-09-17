//! Deterministic offline backend. Derives every answer from a hash of the
//! alert content so runs are reproducible — used by tests and dry runs.

use super::super::alert::Alert;
use super::super::types::{
    ATTACK_CLASSES, ChoiceAnswer, DISPOSITIONS, NoulAnswer, RawAnswers, ScoreAnswer,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Deterministic mock backend. Same alert in, same answers out.
///
/// Test hook: if the alert JSON carries a numeric `mock_delay_ms` field, the
/// backend sleeps that long before answering. Tests use it to force genuine
/// out-of-order completion so the engine's order preservation is exercised
/// for real. Production data never carries this field.
#[derive(Debug, Default)]
pub struct MockBackend;

impl MockBackend {
    pub async fn assess(&self, alert: &Alert) -> Result<RawAnswers, String> {
        let delay_ms = alert
            .raw
            .get("mock_delay_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }

        let mut hasher = DefaultHasher::new();
        alert.raw.to_string().hash(&mut hasher);
        let h = hasher.finish();

        // Avalanche mix: same input → same outputs; different inputs → different ones.
        fn mix(h: u64, salt: u64) -> u64 {
            let mut x = h ^ salt;
            x ^= x >> 33;
            x = x.wrapping_mul(0xff51afd7ed558ccd);
            x ^= x >> 33;
            x
        }

        let pick = |slice: &[&str], salt: u64| -> (String, f64) {
            let m = mix(h, salt);
            let idx = (m % slice.len() as u64) as usize;
            let conf = 0.5 + (m >> 8) as f64 % 50.0 / 100.0;
            (slice[idx].to_string(), conf)
        };

        let (disposition, disposition_confidence) = pick(&DISPOSITIONS, 1);
        let severity_score = (mix(h, 2) % 301) as f64 / 100.0; // 0.00..=3.00
        let severity_confidence = 0.5 + (mix(h, 3) % 50) as f64 / 100.0;
        let fp = (mix(h, 4) % 101) as f64 / 100.0;
        let esc = if disposition == "escalate" || disposition == "contain" {
            0.9 + (mix(h, 5) % 10) as f64 / 100.0
        } else {
            (mix(h, 6) % 100) as f64 / 100.0
        };
        let (attack_class, attack_class_confidence) = pick(&ATTACK_CLASSES, 7);

        Ok(RawAnswers {
            disposition: Some(ChoiceAnswer {
                choice: disposition,
                probabilities: std::collections::BTreeMap::new(),
                confidence: disposition_confidence,
            }),
            severity: Some(ScoreAnswer {
                score: severity_score,
                probabilities: std::collections::BTreeMap::new(),
                confidence: severity_confidence,
            }),
            false_positive_probability: Some(NoulAnswer { noul: fp }),
            requires_escalation: Some(NoulAnswer { noul: esc }),
            attack_class: Some(ChoiceAnswer {
                choice: attack_class,
                probabilities: std::collections::BTreeMap::new(),
                confidence: attack_class_confidence,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::parse_alert;
    use crate::decision::Decision;

    fn alert(line: &str) -> Alert {
        parse_alert(line, 0).unwrap()
    }

    #[tokio::test]
    async fn deterministic_and_valid() {
        let a = alert(r#"{"id":"A-1","rule":"test","command_line":"x"}"#);
        let b = alert(r#"{"id":"A-2","rule":"test","command_line":"y"}"#);

        let r1 = MockBackend.assess(&a).await.unwrap();
        let r2 = MockBackend.assess(&a).await.unwrap();
        assert_eq!(
            format!("{r1:?}"),
            format!("{r2:?}"),
            "same alert → same answers"
        );

        // Different alerts still produce fully valid decisions.
        for r in [&r1, &MockBackend.assess(&b).await.unwrap()] {
            let d = Decision::from_answers(r).expect("mock output must always validate");
            assert!((0.0..=3.0).contains(&d.severity));
            assert!((0.0..=1.0).contains(&d.false_positive_probability));
        }
    }

    #[tokio::test]
    async fn varied_alerts_all_validate() {
        for i in 0..64 {
            let line = format!(r#"{{"id":"A-{i}","rule":"r{i}","command_line":"cmd {i}"}}"#);
            let raw = MockBackend.assess(&alert(&line)).await.unwrap();
            Decision::from_answers(&raw).expect("valid decision");
        }
    }
}
