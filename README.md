# triagedy

> Because alert triage shouldn't be a tragedy.

![ci](https://github.com/m0rphtail/triagedy/actions/workflows/ci.yml/badge.svg)

**Powered by [TypeSafe Jev](https://typesafe.ai) (System One).** 

Alert triage as a UNIX filter: **JSONL security alerts in, typed decisions out.**

One binary. No daemon, no database, no framework. Pipe it, host it, cron it.

```
cat alerts.jsonl | triagedy run | jq '.action'
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
| `jev` | **default, intended path** | TypeSafe System One (`POST /v1/systemone`). Typed answers, calibrated confidence. Needs a key. |
| `openai` | fallback / optional | Any OpenAI-compatible `POST {base}/chat/completions` — Ollama, OpenRouter, vLLM, LM Studio, llama.cpp, Groq. Probes a response-format ladder (`json_schema` → `json_object` → none) once per run and caches what works. Confidence is the model's self-report: **uncalibrated**. `--backend ollama` and `--ollama-url` are accepted as aliases. |
| `mock` | always available | Offline, deterministic. For tests, dry runs, CI. |

The decision shape mirrors TypeSafe's [System One primitives](https://docs.typesafe.ai)
(Choice / Score / Noul), so the fallback path and Jev produce the same records.

### Choosing a model

Jev needs no model flag — `jev-latest` is the service default. For the
`openai` fallback, pick whatever the server serves (`--model`, or
`$TRIAGEDY_MODEL`).

| Where | How |
|---|---|
| Jev (the product) | `--backend jev` (default) — needs a key |
| a hosted OpenAI-compatible API | `--backend openai --openai-url https://… --api-key $OPENAI_API_KEY` |
| any local Ollama model | `--backend openai --model <name>` (see `ollama list`) |

```
# the intended path — Jev (after a one-time `triagedy init`)
triagedy run --backend jev < alerts.jsonl

# fallback: any OpenAI-compatible server
triagedy run --backend openai --model gemma4:e2b --openai-url http://127.0.0.1:11434/v1 < alerts.jsonl
```

### API keys

Never paste a key on the command line — process arguments are visible to other
users via `ps`. Store it once instead:

```
triagedy init          # hidden prompt; writes ~/.config/triagedy/env, mode 0600
triagedy doctor --backend jev
```

Keys are resolved **per backend**: Jev reads `--api-key`, then
`$TYPESAFE_API_KEY`, then the stored file; `openai` reads `--api-key`, then
`$OPENAI_API_KEY`. A key for one is never sent to the other.

> One full-context LLM triage call costs about the same as **1,365 Jev screens**
> — that ratio is why screening every alert first pays for itself.
> (Figures from [Watson Labs' independent TypeSafe deployment write-up](https://blog.watson-labs.co.uk/typesafe-ai-alert-fatigue/).)

## Usage

```
# the intended path — Jev, typed decisions with calibrated confidence
triagedy run < alerts.jsonl

# fallback: any OpenAI-compatible server (Ollama here), same output shape
triagedy run --backend openai --model gemma4:e2b < alerts.jsonl

# pin the fallback model in the environment instead of the command line
TRIAGEDY_MODEL=gemma4:e2b triagedy run --backend openai < alerts.jsonl

# parallel assessments (4 in flight), output order still matches input order
triagedy run --jobs 4 < alerts.jsonl

# files instead of pipes
triagedy run --backend mock --input alerts.jsonl --output decisions.jsonl

# convert a Windows Event Log XML export, then triage it — one pipe
triagedy convert --format sysmon-xml < windows-sysmon.log | triagedy run

# check your backend before a real run
triagedy doctor --backend jev
triagedy doctor --backend openai --model gemma4:e2b
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
cargo build --release        # target/release/triagedy
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
