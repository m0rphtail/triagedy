//! Recent-activity context: decisions from a previous run, fed back into each
//! request so the model can recognise restatements of an incident that is
//! already being handled.
//!
//! The context file is triagedy's own output (JSONL), so a streaming
//! deployment is two commands: run the new batch with the previous output as
//! `--context`. Each run stays a pure function of (alerts, context file) —
//! no hidden state, no dependence on completion order.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// How many recent items travel with each request (newest last).
pub const MAX_CONTEXT_ITEMS: usize = 20;

/// One prior decision, reduced to what the model needs to recognise a repeat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextItem {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Items in file order, newest last.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TriageContext {
    pub items: Vec<ContextItem>,
}

impl TriageContext {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Keep at most [`MAX_CONTEXT_ITEMS`], preserving order (newest last).
    pub fn trimmed(mut self) -> Self {
        if self.items.len() > MAX_CONTEXT_ITEMS {
            let keep = self.items.split_off(self.items.len() - MAX_CONTEXT_ITEMS);
            self.items = keep;
        }
        self
    }
}

/// Parse one line of a previous run's output. Tolerant by design: any JSON
/// object carrying `id` (or `input_index`) works, so output from other tools
/// can serve as context too. Unknown fields are ignored.
pub fn parse_context_line(line: &str) -> Result<ContextItem, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let obj = v.as_object().ok_or("context line must be a JSON object")?;

    let id = obj
        .get("id")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| obj.get("input_index").map(|x| format!("index-{x}")))
        .ok_or("context line needs an `id` or `input_index`")?;

    let s = |k: &str| obj.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let decision = obj.get("decision").and_then(|d| d.as_object());

    Ok(ContextItem {
        id,
        host: s("host"),
        rule: s("rule"),
        action: s("action"),
        disposition: decision
            .and_then(|d| d.get("disposition"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        attack_class: decision
            .and_then(|d| d.get("attack_class"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        timestamp: s("timestamp"),
    })
}

/// Load a context file: parsed items plus the count of skipped lines.
pub fn load_context(path: &Path) -> Result<(TriageContext, usize), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading context file {}: {e}", path.display()))?;
    let mut items = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_context_line(line) {
            Ok(item) => items.push(item),
            Err(_) => skipped += 1,
        }
    }
    Ok((TriageContext { items }.trimmed(), skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_output_record() {
        let line = r#"{"input_index":0,"id":"A-1","ok":true,"host":"WS-1","rule":"r","action":"escalate","timestamp":"t0","decision":{"disposition":"escalate","attack_class":"execution"}}"#;
        let item = parse_context_line(line).unwrap();
        assert_eq!(item.id, "A-1");
        assert_eq!(item.host.as_deref(), Some("WS-1"));
        assert_eq!(item.action.as_deref(), Some("escalate"));
        assert_eq!(item.disposition.as_deref(), Some("escalate"));
        assert_eq!(item.attack_class.as_deref(), Some("execution"));
    }

    #[test]
    fn parses_minimal_id_only_line() {
        let item = parse_context_line(r#"{"id":"only"}"#).unwrap();
        assert_eq!(item.id, "only");
        assert_eq!(item.host, None);
    }

    #[test]
    fn falls_back_to_input_index() {
        assert_eq!(
            parse_context_line(r#"{"input_index":7}"#).unwrap().id,
            "index-7"
        );
    }

    #[test]
    fn rejects_non_objects_and_idless_lines() {
        assert!(parse_context_line("[1,2]").is_err());
        assert!(parse_context_line(r#"{"host":"h"}"#).is_err());
        assert!(parse_context_line("not json").is_err());
    }

    #[test]
    fn keeps_only_the_last_max_items() {
        let items: Vec<ContextItem> = (0..25)
            .map(|i| ContextItem {
                id: format!("A-{i}"),
                host: None,
                rule: None,
                action: None,
                disposition: None,
                attack_class: None,
                timestamp: None,
            })
            .collect();
        let ctx = TriageContext { items }.trimmed();
        assert_eq!(ctx.items.len(), MAX_CONTEXT_ITEMS);
        assert_eq!(ctx.items.first().unwrap().id, "A-5");
        assert_eq!(ctx.items.last().unwrap().id, "A-24");
    }

    #[test]
    fn load_counts_and_skips_bad_lines() {
        let dir = std::env::temp_dir().join(format!("triagedy-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctx.jsonl");
        std::fs::write(&path, "{\"id\":\"a\"}\ngarbage\n\n{\"id\":\"b\"}\n").unwrap();
        let (ctx, skipped) = load_context(&path).unwrap();
        assert_eq!(ctx.items.len(), 2);
        assert_eq!(skipped, 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
