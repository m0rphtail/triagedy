# triage

Alert triage as a UNIX filter: **JSONL alerts in, typed decisions out.**

One binary. No daemon, no database, no framework. Pipe it, host it, cron it.

```
cat alerts.jsonl | triage run --backend ollama | triage-stats
```

## What it does

For each alert it asks five questions and returns a typed, validated decision:

| Question | Type | Answer |
|---|---|---|
| What is the correct triage disposition? | **Choice** | `close` \| `escalate` \| `contain` \| `investigate` + confidence |
| How severe if true positive? | **Score** | 0.0–3.0 + confidence |
| Is this a false positive? | **Noul** | probability 0.0–1.0 |
| Does it need immediate IR escalation? | **Noul** | probability 0.0–1.0 |
| Which attacker technique category? | **Choice** | `none` \| `execution` \| `credential_access` \| `persistence` \| `lateral_movement` \| `exfiltration` |

Then plain, inspectable **code** routes the decision to an action — the model
judges, the code decides what to do.

## Backends

| Backend | Status | Notes |
|---|---|---|
| `mock` | always available | offline, deterministic; for tests, dry runs, pipelines |
| `ollama` | works today | any local model; JSON-schema-constrained; needs `think:false` support for reasoning models |
| `jev` | wired, awaiting access | TypeSafe System One API (`POST /v1/systemone`), calibrated probabilities |

The decision shape mirrors TypeSafe's [System One primitives](https://docs.typesafe.ai)
(Choice / Score / Noul), so moving from a local model to Jev is a flag change:

```
# today
triage run --backend ollama --model gemma4:e2b < alerts.jsonl

# when Jev access lands
TYPESAFE_API_KEY=... triage run --backend jev < alerts.jsonl
```

## Usage

```
# assess alerts from stdin → JSONL decisions on stdout
triage run --backend ollama --model gemma4:e2b < alerts.jsonl

# parallel assessments (4 in flight), output order still matches input order
triage run --backend ollama --jobs 4 < alerts.jsonl

# files instead of pipes
triage run --backend mock --input alerts.jsonl --output decisions.jsonl

# check your backend before a real run
triage doctor --backend ollama --model gemma4:e2b
```

Exit codes: `0` all records ok, `1` at least one record failed, `2` config/runtime error.

### Output record

One JSON object per input alert, **in input order** (parallelism never reorders):

```json
{
  "input_index": 0,
  "id": "alert-0001",
  "ok": true,
  "backend": "ollama",
  "model": "gemma4:e2b",
  "rule": "Suspicious process execution",
  "host": "WORKSTATION-01",
  "user": "CORP\\analyst",
  "decision": {
    "disposition": "investigate",
    "disposition_confidence": 0.85,
    "severity": 2.5,
    "severity_confidence": 0.9,
    "false_positive_probability": 0.15,
    "requires_escalation": 0.7,
    "attack_class": "execution",
    "attack_class_confidence": 0.95
  },
  "action": "investigate",
  "review_required": false,
  "notes": []
}
```

Bad input lines produce an error record (`"ok": false`, `"error": "..."`) and
never take down the batch.

## How routing works

The policy lives in `src/policy.rs` — ordinary Rust, no prompts:

1. The disposition leads: `escalate` → escalate, `contain` → contain.
2. A `close` verdict must survive a false-positive-probability gate that gets
   stricter as severity rises (fp ≥ 0.5, or ≥ 0.7 at severity ≥ 2.0).
3. `investigate` upgrades to `escalate` when `requires_escalation ≥ 0.9` **and**
   `severity ≥ 2.0`.
4. Any confidence below 0.6 sets `review_required` with a note explaining why.

Change the thresholds and the tests in the same file tell you what you broke.

## Build

Requires a Rust toolchain (edition 2024):

```
cargo build --release        # target/release/triage
cargo test                   # 25 tests: unit + end-to-end, no network needed
cargo clippy --all-targets   # clean
```

The test suite covers: alert parsing across vendor key schemes, decision
validation (bad options and bad ranges are rejected), policy routing, mock
determinism, output-order preservation under forced out-of-order completion,
per-record failure isolation, and the full CLI via spawned processes.

## Design notes

- **Order-preserving parallelism**: `futures::stream::buffered`, not
  `unordered`. Record N always corresponds to alert N.
- **Validation is not optional**: every backend output is checked against the
  defined option sets and ranges before it becomes a decision. An invalid
  answer is an error record, never a silent default.
- **Confidence honesty**: with the `ollama` backend, confidence values are the
  model's self-report — treat them as *uncalibrated*. Jev returns calibrated
  probabilities; that swap is exactly what this pipeline was built for.
- **Self-contained records**: the output carries the alert's identifying
  fields, so a downstream tool needs no join back to the input.

## Fixtures

`fixtures/alerts.jsonl` — 8 realistic alerts (encoded PowerShell, LSASS access,
RDP brute-force-then-success, sanctioned maintenance, authorized scanner, DLP
exfil, new admin account, temp-path rundll32) covering every disposition.
