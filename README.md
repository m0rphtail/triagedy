# triagedy

> Because alert triage shouldn't be a tragedy.

![ci](https://github.com/m0rphtail/triagedy/actions/workflows/ci.yml/badge.svg)

**Powered by [TypeSafe Jev](https://typesafe.ai) (System One).** Typed decisions
with calibrated probabilities in ~200 ms, at $0.042/Mtok — a screen cheap enough
to put in front of *every* alert, so your expensive triage (and your humans)
only see what survives it.

Alert triage as a UNIX filter: **JSONL security alerts in, typed decisions out.**

One binary. No daemon, no database, no framework. Pipe it, host it, cron it.

```
cat alerts.jsonl | triagedy run | jq '.action'
```

Not ready for Jev, or need to keep data on-prem? Point `--backend openai` at any
OpenAI-compatible server — Ollama, vLLM, LM Studio, llama.cpp, OpenRouter — and
the pipeline is identical.

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
| `jev` | **default, intended path** | TypeSafe System One (`POST /v1/systemone`). Typed answers, calibrated confidence. Needs a key: `triagedy init`. |
| `openai` | fallback / optional | Any OpenAI-compatible `POST {base}/chat/completions` — Ollama, OpenRouter, vLLM, LM Studio, llama.cpp, Groq. Probes a response-format ladder (`json_schema` → `json_object` → none) once per run and caches what works. Confidence is the model's self-report: **uncalibrated**. `--backend ollama` and `--ollama-url` are accepted as aliases. |
| `mock` | always available | Offline, deterministic. For tests, dry runs, CI. |

The decision shape mirrors TypeSafe's [System One primitives](https://docs.typesafe.ai)
(Choice / Score / Noul), so the fallback path and Jev produce the same records.

### Choosing a model

Jev needs no model flag — `jev-latest` is the service default. For the
`openai` fallback, pick whatever the server serves (`--model`, or
`$TRIAGEDY_MODEL`); with no model given, triagedy stops with a config error
rather than guessing.

| Where | How |
|---|---|
| Jev (the product) | `--backend jev` (default) — needs a key |
| any local Ollama model | `--backend openai --model <name>` (see `ollama list`) |
| a hosted OpenAI-compatible API | `--backend openai --openai-url https://… --api-key $OPENAI_API_KEY` |
| a model too big for your box | an Ollama cloud model — `ollama signin`, `-cloud` tags |
| your own transport | add a variant in `src/backends/` — one `assess()` method |

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

## Smoke test

No alert data ships with this repo — alert corpora stay local, and the
`fixtures/` directory is gitignored. Supply your own JSONL.

Recorded run: RPi5 (16 GB, 4 cores, CPU inference), 8 synthetic alerts covering
every disposition, `--model gemma4:e2b --jobs 1`, **8/8 records ok, 490 s**
(~61 s/alert):

| Alert | Expected | Got | Verdict |
|---|---|---|---|
| Encoded PowerShell from Word | escalate/investigate | `investigate` (execution) | ✅ |
| rundll32 from temp path | escalate/investigate | `investigate` (execution) | ✅ |
| LSASS access from Downloads | escalate/investigate | `investigate` (credential_access) | ✅ |
| Sanctioned GPO maintenance w/ change ticket | close | `close` (none) | ✅ |
| Authorized scanner (asset registry says so) | close | `close` (none) | ✅ |
| RDP brute-force → success from TOR exit | escalate/contain | `investigate` (credential_access) | ⚠️ conservative |
| Encrypted archive outbound from DB server | escalate/contain | `investigate` (exfiltration) | ⚠️ conservative |
| New admin account, no change ticket | investigate | `investigate` (credential_access) | ✅ |

6/8 exact disposition, **zero dangerous errors** — both deviations flag for
investigation instead of escalating or containing, and nothing malicious was
dismissed. The two closes the model got right both had machine-readable
evidence in the alert (change ticket, asset registry), which is the prompt's
intended behavior. This is uncalibrated local-model behavior; the remaining
gaps are exactly what a calibrated model and a prompt/tuning pass are for.
Re-running the same private corpus against Jev when access lands is the
calibration benchmark.

Operational note on small hardware: the model is the whole memory story —
`gemma4:e2b` sits at ~6.8 GB resident once loaded, and `ollama ps` shows it
until it idles out. On a 16 GB box keep one inference slot (`--jobs 1`) so the
model, the pipeline, and your shell all fit in RAM; a second slot or a parallel
`cargo build` is what pushes the machine into swap. For quick iteration use
`--backend mock`; the engine is I/O-bound on the model, not the pipeline.
