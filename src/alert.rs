//! Alert parsing: one line of JSONL in, one normalized `Alert` out.
//!
//! Alerts come in many shapes (Sysmon, Defender, CrowdStrike, Splunk...).
//! We keep the entire original object in `raw` — that is what gets sent to
//! the model — and pick out a few common fields for output convenience.

use serde_json::Value;

/// A parsed alert. `raw` is always the full original JSON object.
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: String,
    pub rule: Option<String>,
    pub severity: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub process: Option<String>,
    pub command_line: Option<String>,
    pub parent_process: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub timestamp: Option<String>,
    pub raw: Value,
}

const ID_KEYS: [&str; 5] = ["id", "alert_id", "alertId", "_id", "event_id"];
const RULE_KEYS: [&str; 7] = [
    "rule",
    "rule_name",
    "ruleName",
    "signature",
    "title",
    "event_type",
    "name",
];
const SEVERITY_KEYS: [&str; 3] = ["severity", "level", "priority"];
const HOST_KEYS: [&str; 5] = ["host", "hostname", "computer", "device", "endpoint"];
const USER_KEYS: [&str; 5] = ["user", "username", "account", "userName", "src_user"];
const PROCESS_KEYS: [&str; 5] = ["process", "process_name", "image", "proc", "exe"];
const CMDLINE_KEYS: [&str; 4] = ["command_line", "commandLine", "cmdline", "command"];
const PARENT_KEYS: [&str; 5] = [
    "parent_process",
    "parentProcess",
    "parent_image",
    "parentProcessName",
    "parent",
];
const SRC_IP_KEYS: [&str; 6] = [
    "src_ip",
    "source_ip",
    "srcip",
    "sourceIp",
    "src",
    "sourceAddress",
];
const DST_IP_KEYS: [&str; 6] = [
    "dst_ip",
    "destination_ip",
    "dstip",
    "dest_ip",
    "dst",
    "destinationAddress",
];
const TS_KEYS: [&str; 5] = [
    "timestamp",
    "time",
    "@timestamp",
    "event_time",
    "created_at",
];

/// Parse one JSONL line into an `Alert`. `idx` is the 0-based index of the
/// input record and is used to synthesize an id when the alert has none.
pub fn parse_alert(line: &str, idx: usize) -> Result<Alert, String> {
    let raw: Value = serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    if !raw.is_object() {
        return Err("alert must be a JSON object".to_string());
    }
    let id = get(&raw, &ID_KEYS).unwrap_or_else(|| format!("auto-{idx}"));
    Ok(Alert {
        id,
        rule: get(&raw, &RULE_KEYS),
        severity: get(&raw, &SEVERITY_KEYS),
        host: get(&raw, &HOST_KEYS),
        user: get(&raw, &USER_KEYS),
        process: get(&raw, &PROCESS_KEYS),
        command_line: get(&raw, &CMDLINE_KEYS),
        parent_process: get(&raw, &PARENT_KEYS),
        src_ip: get(&raw, &SRC_IP_KEYS),
        dst_ip: get(&raw, &DST_IP_KEYS),
        timestamp: get(&raw, &TS_KEYS),
        raw,
    })
}

/// First present, non-empty value among `keys` (supports dotted paths).
fn get(v: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(val) = lookup(v, key) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            } else if let Some(n) = val.as_f64() {
                return Some(if n.fract() == 0.0 {
                    format!("{}", n as i64)
                } else {
                    n.to_string()
                });
            } else if let Some(b) = val.as_bool() {
                return Some(b.to_string());
            }
        }
    }
    None
}

fn lookup<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    if let Some((head, tail)) = key.split_once('.') {
        v.get(head).and_then(|inner| lookup(inner, tail))
    } else {
        v.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sysmon_style_alert() {
        let line = r#"{"id":"A-1","rule":"Encoded PowerShell","severity":"high","host":"WS-1","user":"CORP\\jdoe","process":"powershell.exe","command_line":"powershell -enc ...","timestamp":"2026-09-17T03:41:22Z"}"#;
        let a = parse_alert(line, 0).unwrap();
        assert_eq!(a.id, "A-1");
        assert_eq!(a.rule.as_deref(), Some("Encoded PowerShell"));
        assert_eq!(a.host.as_deref(), Some("WS-1"));
        assert_eq!(a.process.as_deref(), Some("powershell.exe"));
    }

    #[test]
    fn parses_alt_keys_and_dotted_paths() {
        let line = r#"{"event_id":42,"name":"Suspicious login","computer":"VPN-GW","level":"medium","source_ip":"203.0.113.9","@timestamp":"2026-09-17T00:00:00Z"}"#;
        let a = parse_alert(line, 5).unwrap();
        assert_eq!(a.id, "42");
        assert_eq!(a.rule.as_deref(), Some("Suspicious login"));
        assert_eq!(a.host.as_deref(), Some("VPN-GW"));
        assert_eq!(a.src_ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn synthesizes_id_and_defaults_missing_fields() {
        let a = parse_alert(r#"{"rule":"bare"}"#, 7).unwrap();
        assert_eq!(a.id, "auto-7");
        assert_eq!(a.rule.as_deref(), Some("bare"));
        assert!(a.host.is_none());
        assert!(a.timestamp.is_none());
    }

    #[test]
    fn rejects_non_object_and_bad_json() {
        assert!(parse_alert("not json", 0).is_err());
        assert!(parse_alert("[1,2,3]", 0).is_err());
        assert!(parse_alert(r#""just a string""#, 0).is_err());
    }
}
