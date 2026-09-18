//! `triagedy convert`: read telemetry exports and write the JSONL that
//! `triagedy run` consumes.
//!
//! Elastic ECS and CrowdStrike FDR are already JSON, so `run` reads them
//! natively (see the key lists in `src/alert.rs`). Windows Event Log XML is
//! not, so it needs this converter. Keeping it in the binary means one
//! artifact to deploy — no Python on the target host.
//!
//! Safety: `roxmltree` parses with `allow_dtd` off by default, so DTDs and
//! entity declarations are rejected outright — no XXE surface, no
//! billion-laughs expansion.

use anyhow::{Context as _, anyhow};
use roxmltree::{Document, Node};
use serde_json::{Map, Value};
use std::io::{BufRead, Write};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConvertStats {
    pub converted: usize,
    pub skipped: usize,
}

pub const SUPPORTED_FORMATS: [&str; 3] = ["sysmon-xml", "xml", "wineventlog"];

pub fn convert_stream<R: BufRead, W: Write>(
    input: R,
    out: &mut W,
    format: &str,
) -> anyhow::Result<ConvertStats> {
    if !SUPPORTED_FORMATS.contains(&format) {
        return Err(anyhow!(
            "unsupported format '{format}' (supported: sysmon-xml)"
        ));
    }
    let mut stats = ConvertStats::default();
    for line in input.lines() {
        let line = line.context("reading input line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match convert_event(line) {
            Ok(value) => {
                writeln!(out, "{}", serde_json::to_string(&value)?)?;
                stats.converted += 1;
            }
            Err(_) => stats.skipped += 1,
        }
    }
    out.flush()?;
    Ok(stats)
}

/// One `<Event>…</Event>` line → one JSON object. Field names match
/// `tools/sysmon_xml_to_jsonl.py` so downstream is identical.
fn convert_event(xml: &str) -> Result<Value, String> {
    let doc = Document::parse(xml).map_err(|e| format!("xml parse: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "Event" {
        return Err("not an <Event> element".to_string());
    }
    let find = |name: &str| {
        root.descendants()
            .find(|n: &Node| n.is_element() && n.tag_name().name() == name)
    };

    let mut obj = Map::new();

    if let Some(e) = find("EventID") {
        let text = e.text().unwrap_or("").trim().to_string();
        if !text.is_empty() {
            let value = text
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::from(text));
            obj.insert("event_id".to_string(), value);
        }
    }
    if let Some(c) = find("Computer")
        && let Some(t) = c.text()
        && !t.trim().is_empty()
    {
        obj.insert("computer".to_string(), Value::from(t.trim()));
    }
    if let Some(tc) = find("TimeCreated")
        && let Some(stamp) = tc.attribute("SystemTime")
    {
        obj.insert("timestamp".to_string(), Value::from(stamp));
    }
    if let Some(p) = find("Provider")
        && let Some(name) = p.attribute("Name")
    {
        obj.insert("provider".to_string(), Value::from(name));
    }
    if let Some(ch) = find("Channel")
        && let Some(t) = ch.text()
    {
        obj.insert("channel".to_string(), Value::from(t.trim()));
    }
    if let Some(r) = find("EventRecordID")
        && let Some(t) = r.text()
    {
        obj.insert("event_record_id".to_string(), Value::from(t.trim()));
    }
    if let Some(l) = find("Level")
        && let Some(t) = l.text()
    {
        obj.insert("level".to_string(), Value::from(t.trim()));
    }

    let mut data = Map::new();
    for d in root.descendants() {
        if d.is_element()
            && d.tag_name().name() == "Data"
            && let Some(name) = d.attribute("Name")
        {
            let text = d.text().unwrap_or("").trim().to_string();
            if !text.is_empty() {
                data.insert(name.to_string(), Value::from(text));
            }
        }
    }
    if !data.is_empty() {
        obj.insert("event_data".to_string(), Value::Object(data.clone()));
    }

    hoist(
        &mut obj,
        &data,
        "process",
        &["Image", "NewProcessName", "ProcessName"],
    );
    hoist(
        &mut obj,
        &data,
        "command_line",
        &["CommandLine", "ProcessCommandLine"],
    );
    hoist(
        &mut obj,
        &data,
        "parent_process",
        &["ParentImage", "ParentProcessName"],
    );
    hoist(
        &mut obj,
        &data,
        "user",
        &["User", "SubjectUserName", "TargetUserName"],
    );
    hoist(&mut obj, &data, "rule", &["RuleName", "Description"]);
    hoist(
        &mut obj,
        &data,
        "src_ip",
        &["SourceIp", "SourceAddress", "IpAddress"],
    );
    hoist(&mut obj, &data, "dst_ip", &["DestinationIp", "DestAddress"]);

    let host = obj
        .get("computer")
        .and_then(Value::as_str)
        .unwrap_or("unknown-host")
        .to_string();
    let id = match obj.get("event_record_id").and_then(Value::as_str) {
        Some(record) => format!("{host}-{record}"),
        None => match obj.get("event_id") {
            Some(eid) => format!("{host}-eid{eid}"),
            None => format!("{host}-unknown"),
        },
    };
    obj.insert("id".to_string(), Value::from(id));

    Ok(Value::Object(obj))
}

fn hoist(obj: &mut Map<String, Value>, data: &Map<String, Value>, target: &str, sources: &[&str]) {
    for source in sources {
        if let Some(Value::String(text)) = data.get(*source)
            && !text.is_empty()
        {
            obj.insert(target.to_string(), Value::from(text.clone()));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID><TimeCreated SystemTime='2021-01-19T13:27:04.923423100Z'/><EventRecordID>33445</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-dc-397.attackrange.local</Computer><Level>4</Level></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -Exec bypass -enc AAAA</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='User'>ATTACKRANGE\Administrator</Data></EventData></Event>"#;

    #[test]
    fn converts_one_event() {
        let v = convert_event(SAMPLE).unwrap();
        assert_eq!(v["event_id"], 1);
        assert_eq!(v["computer"], "win-dc-397.attackrange.local");
        assert_eq!(v["timestamp"], "2021-01-19T13:27:04.923423100Z");
        assert_eq!(v["event_record_id"], "33445");
        assert_eq!(
            v["event_data"]["CommandLine"],
            "powershell.exe -Exec bypass -enc AAAA"
        );
        assert_eq!(
            v["process"],
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(v["parent_process"], r"C:\Windows\System32\cmd.exe");
        assert_eq!(v["user"], r"ATTACKRANGE\Administrator");
        assert_eq!(v["id"], "win-dc-397.attackrange.local-33445");
    }

    #[test]
    fn counts_skips_and_rejects_unknown_formats() {
        assert!(convert_event("<NotAnEvent/>").is_err());
        let input = format!("{SAMPLE}\n<broken\n\n");
        let mut out = Vec::new();
        let stats = convert_stream(std::io::Cursor::new(input), &mut out, "sysmon-xml").unwrap();
        assert_eq!(stats.converted, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 1);

        let mut out = Vec::new();
        assert!(convert_stream(std::io::Cursor::new(""), &mut out, "nope").is_err());
    }

    #[test]
    fn rejects_dtd_and_entity_declarations() {
        // roxmltree has allow_dtd off by default: a DTD must not parse, which
        // is what closes the XXE and billion-laughs holes.
        let with_dtd = r#"<?xml version="1.0"?><!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Event><System><Computer>&xxe;</Computer></System></Event>"#;
        assert!(convert_event(with_dtd).is_err());
    }

    #[test]
    fn converted_output_parses_as_a_triagedy_alert() {
        let v = convert_event(SAMPLE).unwrap();
        let line = serde_json::to_string(&v).unwrap();
        let alert = crate::alert::parse_alert(&line, 0).unwrap();
        assert_eq!(alert.id, "win-dc-397.attackrange.local-33445");
        assert_eq!(
            alert.command_line.as_deref(),
            Some("powershell.exe -Exec bypass -enc AAAA")
        );
        assert_eq!(alert.host.as_deref(), Some("win-dc-397.attackrange.local"));
    }
}
