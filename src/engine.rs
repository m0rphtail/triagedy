//! The pipeline: JSONL alerts in, one JSONL decision record per alert out.
//!
//! - order-preserving: output record N always corresponds to input alert N,
//!   regardless of which future finishes first (`buffered`, not `unordered`)
//! - bounded: at most `jobs` assessments in flight
//! - isolated: one bad alert (parse or backend failure) becomes an error
//!   record; it never takes down the batch

use crate::alert::Alert;
use crate::backends::Backends;
use crate::decision::Decision;
use crate::policy::{Action, Assessment, assess as route};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::io::{BufRead, Write};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStats {
    pub total: usize,
    pub ok: usize,
    pub failed: usize,
}

/// One output record. Success records carry the typed decision, the routed
/// action, and any review notes. Failure records carry the error message and
/// as much alert identity as could be parsed.
#[derive(Debug, Serialize)]
pub struct OutputRecord {
    /// 0-based line number of the alert in the input.
    pub input_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub ok: bool,
    pub backend: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Read `input`, assess every non-blank line, and write one JSON record per
/// alert to `out` in input order.
pub async fn run<R: BufRead, W: Write>(
    mut input: R,
    out: &mut W,
    backend: &Backends,
    backend_name: &str,
    model: &str,
    jobs: usize,
    context: Option<&crate::context::TriageContext>,
) -> anyhow::Result<RunStats> {
    let mut items: Vec<(usize, String)> = Vec::new();
    for (idx, line) in input.by_ref().lines().enumerate() {
        let line = line.map_err(|e| anyhow::anyhow!("reading input line {idx}: {e}"))?;
        if line.trim().is_empty() {
            continue; // blank lines are skipped, not counted
        }
        items.push((idx, line));
    }

    let jobs = jobs.max(1);
    let mut stats = RunStats {
        total: items.len(),
        ok: 0,
        failed: 0,
    };

    let mut stream = stream::iter(items.into_iter().map(|(idx, line)| async move {
        process_line(backend, backend_name, model, idx, &line, context).await
    }))
    .buffered(jobs);

    while let Some(record) = stream.next().await {
        if record.ok {
            stats.ok += 1;
        } else {
            stats.failed += 1;
        }
        let line = serde_json::to_string(&record)
            .map_err(|e| anyhow::anyhow!("serializing output record: {e}"))?;
        writeln!(out, "{line}")?;
    }
    out.flush()?;

    Ok(stats)
}

async fn process_line(
    backend: &Backends,
    backend_name: &str,
    model: &str,
    idx: usize,
    line: &str,
    context: Option<&crate::context::TriageContext>,
) -> OutputRecord {
    let alert = match crate::alert::parse_alert(line, idx) {
        Ok(a) => a,
        Err(e) => {
            return err_record(
                idx,
                None,
                None,
                backend_name,
                model,
                format!("parse error: {e}"),
            );
        }
    };

    let raw = match backend.assess(&alert, context).await {
        Ok(r) => r,
        Err(e) => {
            return err_record(
                idx,
                Some(alert.id.clone()),
                alert.rule.clone(),
                backend_name,
                model,
                format!("assess error: {e}"),
            );
        }
    };

    match Decision::from_answers(&raw) {
        Ok(decision) => {
            let assessment = route(&decision);
            ok_record(idx, &alert, backend_name, model, decision, assessment)
        }
        Err(e) => err_record(
            idx,
            Some(alert.id.clone()),
            alert.rule.clone(),
            backend_name,
            model,
            format!("decision error: {e}"),
        ),
    }
}

fn ok_record(
    idx: usize,
    alert: &Alert,
    backend_name: &str,
    model: &str,
    decision: Decision,
    assessment: Assessment,
) -> OutputRecord {
    OutputRecord {
        input_index: idx,
        id: Some(alert.id.clone()),
        ok: true,
        backend: backend_name.to_string(),
        model: model.to_string(),
        rule: alert.rule.clone(),
        severity: alert.severity.clone(),
        host: alert.host.clone(),
        user: alert.user.clone(),
        process: alert.process.clone(),
        command_line: alert.command_line.clone(),
        parent_process: alert.parent_process.clone(),
        src_ip: alert.src_ip.clone(),
        dst_ip: alert.dst_ip.clone(),
        timestamp: alert.timestamp.clone(),
        decision: Some(decision),
        action: Some(assessment.action),
        review_required: Some(assessment.review_required),
        notes: Some(assessment.notes),
        error: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn err_record(
    idx: usize,
    id: Option<String>,
    rule: Option<String>,
    backend_name: &str,
    model: &str,
    error: String,
) -> OutputRecord {
    OutputRecord {
        input_index: idx,
        id,
        ok: false,
        backend: backend_name.to_string(),
        model: model.to_string(),
        rule,
        severity: None,
        host: None,
        user: None,
        process: None,
        command_line: None,
        parent_process: None,
        src_ip: None,
        dst_ip: None,
        timestamp: None,
        decision: None,
        action: None,
        review_required: None,
        notes: None,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::mock::MockBackend;

    fn parse_records(out: &[u8]) -> Vec<serde_json::Value> {
        String::from_utf8(out.to_vec())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).expect("output must be valid JSONL"))
            .collect()
    }

    #[tokio::test]
    async fn preserves_order_under_out_of_order_completion() {
        // Descending delays: later records finish first. Output must still be
        // in input order — this is the buffered-vs-unordered guarantee, and
        // the `mock_delay_ms` hook makes it a real race, not an assumed one.
        let input: String = (0..6)
            .map(|i| {
                format!(
                    r#"{{"id":"A-{i}","rule":"r{i}","mock_delay_ms":{}}}"#,
                    (6 - i) * 30
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        let started = std::time::Instant::now();
        let stats = run(
            std::io::Cursor::new(input),
            &mut out,
            &backend,
            "mock",
            "mock",
            6,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            stats,
            RunStats {
                total: 6,
                ok: 6,
                failed: 0
            }
        );
        // If this ran serially, it would take ~450ms; parallel ≈ max delay 180ms.
        assert!(
            started.elapsed().as_millis() < 400,
            "expected parallel execution"
        );

        let records = parse_records(&out);
        assert_eq!(records.len(), 6);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r["input_index"], i as u64, "record {i} out of order");
            assert_eq!(r["id"], format!("A-{i}"));
            assert_eq!(r["ok"], true);
            assert!(r["action"].is_string());
            assert!(r["decision"]["severity"].is_number());
            assert!(r["review_required"].is_boolean());
        }
    }

    #[tokio::test]
    async fn isolates_failures_per_record() {
        let input =
            "{\"id\":\"a\",\"rule\":\"ok\"}\nnot json\n{\"id\":\"c\",\"rule\":\"ok\"}\n[1,2]\n";
        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        let stats = run(
            std::io::Cursor::new(input),
            &mut out,
            &backend,
            "mock",
            "mock",
            2,
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            stats,
            RunStats {
                total: 4,
                ok: 2,
                failed: 2
            }
        );
        let records = parse_records(&out);
        assert_eq!(records.len(), 4);
        assert_eq!(records[0]["ok"], true);
        assert_eq!(records[1]["ok"], false);
        assert!(
            records[1]["error"]
                .as_str()
                .unwrap()
                .contains("invalid JSON")
        );
        assert!(records[1].get("id").is_none());
        assert_eq!(records[2]["ok"], true);
        assert_eq!(records[3]["ok"], false);
        assert!(
            records[3]["error"]
                .as_str()
                .unwrap()
                .contains("must be a JSON object")
        );
    }

    #[tokio::test]
    async fn skips_blank_lines_and_indexes_by_line_number() {
        let input = "{\"id\":\"a\"}\n\n{\"id\":\"b\"}\n";
        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        let stats = run(
            std::io::Cursor::new(input),
            &mut out,
            &backend,
            "mock",
            "mock",
            1,
            None,
        )
        .await
        .unwrap();

        assert_eq!(stats.total, 2);
        let records = parse_records(&out);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["input_index"], 2);
    }

    #[tokio::test]
    async fn empty_input_produces_empty_output() {
        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        let stats = run(
            std::io::Cursor::new(""),
            &mut out,
            &backend,
            "mock",
            "mock",
            4,
            None,
        )
        .await
        .unwrap();
        assert_eq!(stats, RunStats::default());
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn context_produces_a_duplicate_probability() {
        use crate::context::{ContextItem, TriageContext};
        let ctx = TriageContext {
            items: vec![ContextItem {
                id: "prev-1".into(),
                host: Some("WS-1".into()),
                rule: None,
                action: None,
                disposition: None,
                attack_class: None,
                timestamp: None,
            }],
        };
        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        let stats = run(
            std::io::Cursor::new("{\"id\":\"n1\"}\n"),
            &mut out,
            &backend,
            "mock",
            "mock",
            1,
            Some(&ctx),
        )
        .await
        .unwrap();
        assert_eq!(stats.ok, 1);
        let rec: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
        assert!(rec["decision"]["duplicate_probability"].is_number());
    }

    #[tokio::test]
    async fn no_context_leaves_the_field_out() {
        let backend = Backends::Mock(MockBackend);
        let mut out: Vec<u8> = Vec::new();
        run(
            std::io::Cursor::new("{\"id\":\"n1\"}\n"),
            &mut out,
            &backend,
            "mock",
            "mock",
            1,
            None,
        )
        .await
        .unwrap();
        let rec: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
        assert!(rec["decision"].get("duplicate_probability").is_none());
    }
}
