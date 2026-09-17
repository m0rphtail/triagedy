//! End-to-end CLI tests: run the real binary with the mock backend.
//! No network, no models, deterministic.

use std::io::Write;
use std::process::{Command, Stdio};

fn triagedy_bin() -> &'static str {
    env!("CARGO_BIN_EXE_triagedy")
}

fn run_cli(args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut child = Command::new(triagedy_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn triagedy");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("stdout utf8"),
        String::from_utf8(out.stderr).expect("stderr utf8"),
    )
}

#[test]
fn mock_end_to_end_jsonl() {
    let input = concat!(
        r#"{"id":"A-1","rule":"Encoded PowerShell","severity":"high","host":"WS-1"}"#,
        "\n",
        r#"{"id":"A-2","rule":"Scheduled task update","severity":"low","host":"WS-2"}"#,
        "\n",
        "not json\n",
    );

    let (code, stdout, stderr) = run_cli(
        &["run", "--backend", "mock", "--jobs", "2", "--quiet"],
        input,
    );

    // One bad line → exit 1, but every input line still yields a record.
    assert_eq!(code, Some(1), "stderr: {stderr}");
    let records: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSONL"))
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["ok"], true);
    assert_eq!(records[0]["id"], "A-1");
    assert_eq!(records[1]["ok"], true);
    assert_eq!(records[2]["ok"], false);
    assert_eq!(records[2]["input_index"], 2);
    for r in &records[..2] {
        assert!(r["decision"].is_object());
        assert!(r["action"].is_string());
        assert!(r["review_required"].is_boolean());
        assert_eq!(r["backend"], "mock");
    }
}

#[test]
fn all_valid_input_exits_zero() {
    let input = "{\"id\":\"A-1\",\"rule\":\"r\"}\n{\"id\":\"A-2\",\"rule\":\"r\"}\n";
    let (code, stdout, _) = run_cli(&["run", "--backend", "mock", "--quiet"], input);
    assert_eq!(code, Some(0));
    assert_eq!(stdout.lines().count(), 2);
}

#[test]
fn output_order_matches_input_order_with_parallel_workers() {
    let input: String = (0..8)
        .map(|i| format!(r#"{{"id":"A-{i}","mock_delay_ms":{}}}"#, (8 - i) * 25))
        .collect::<Vec<_>>()
        .join("\n");

    let (code, stdout, _) = run_cli(
        &["run", "--backend", "mock", "--jobs", "8", "--quiet"],
        &input,
    );
    assert_eq!(code, Some(0));

    let records: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSONL"))
        .collect();
    assert_eq!(records.len(), 8);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r["input_index"], i as u64, "out of order at {i}");
        assert_eq!(r["id"], format!("A-{i}"));
    }
}

#[test]
fn doctor_mock_succeeds() {
    let out = Command::new(triagedy_bin())
        .args(["doctor", "--backend", "mock"])
        .output()
        .expect("run doctor");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("mock backend"));
}

#[test]
fn ollama_without_a_model_is_a_config_error() {
    // No model is baked into the binary: the caller picks one, by flag or env.
    let out = Command::new(triagedy_bin())
        .args(["run", "--backend", "ollama"])
        .env_remove("TRIAGEDY_MODEL")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no model selected"), "stderr was: {stderr}");
}

#[test]
fn ollama_model_can_come_from_the_environment() {
    // TRIAGEDY_MODEL is honored: the run gets past model resolution and fails
    // at the transport instead (port 1 on loopback is closed), which is the
    // proof that a model name was accepted without any model being pinned.
    let out = Command::new(triagedy_bin())
        .args([
            "run",
            "--backend",
            "ollama",
            "--ollama-url",
            "http://127.0.0.1:1",
            "--quiet",
        ])
        .env("TRIAGEDY_MODEL", "any-model-local-or-cloud")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .take()
                .expect("stdin")
                .write_all(b"{\"id\":\"A-1\"}\n")?;
            c.wait_with_output()
        })
        .expect("run");
    // One alert, one failed record: the run reached the transport, so the
    // model name was accepted — and the record echoes back which model ran.
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let record: serde_json::Value =
        serde_json::from_str(stdout.lines().next().expect("one record")).expect("valid JSON");
    assert_eq!(record["ok"], false);
    assert_eq!(record["model"], "any-model-local-or-cloud");
    assert!(
        record["error"]
            .as_str()
            .expect("error string")
            .contains("ollama"),
        "record was: {record}"
    );
}

#[test]
fn unknown_backend_is_a_config_error() {
    let out = Command::new(triagedy_bin())
        .args(["run", "--backend", "nope"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown backend"));
}

#[test]
fn summary_line_reports_counts() {
    let input = "{\"id\":\"a\"}\n{\"id\":\"b\"}\nbad\n";
    let (code, _stdout, stderr) = run_cli(&["run", "--backend", "mock"], input);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("3 records, 2 ok, 1 failed"),
        "stderr was: {stderr}"
    );
}
