# triagedy

> Because alert triage shouldn't be a tragedy.

![ci](https://github.com/m0rphtail/triagedy/actions/workflows/ci.yml/badge.svg)

Alert triage as a UNIX filter: **JSONL alerts in, typed decisions out.**

One binary. No daemon, no database, no framework. Pipe it, host it, cron it.

```
cat alerts.jsonl | triagedy run --backend ollama | jq '.action'
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
| `ollama` | works today | any model the server serves — local or cloud; JSON-schema-constrained; handles thinking models |
| `jev` | **live** | TypeSafe System One API (`POST /v1/systemone`), calibrated probabilities — needs an API key (`triagedy init`) |

The decision shape mirrors TypeSafe's [System One primitives](https://docs.typesafe.ai)
(Choice / Score / Noul), so moving from a local model to Jev is a flag change:

### Choosing a model

**No model is baked into the binary.** triagedy drives whatever you point it
at, so the same binary fits a laptop, a Pi, a GPU box, or a hosted model:

| Where | How |
|---|---|
| any local Ollama model | `--model <name>` (see `ollama list`) |
| a model too big for your box | an Ollama cloud model — sign in with `ollama signin`; cloud models show up with a `-cloud` tag |
| a different server | `--ollama-url` |
| the Jev service | `--backend jev` (+ `TYPESAFE_API_KEY`) |
| your own transport | add a variant in `src/backends/` — one `assess()` method |

Resolution order is `--model`, then `$TRIAGEDY_MODEL`, then nothing: with the
`ollama` backend and no model given, triagedy stops with a config error rather
than guessing. Pick a model that fits your hardware — the model is the only
heavy part, and it loads once per run.

```
# local model, today
triagedy run --backend ollama --model gemma4:e2b < alerts.jsonl

# Jev (TypeSafe System One) — after `triagedy init`
triagedy run --backend jev < alerts.jsonl
```

### API keys

Never paste a key on the command line — process arguments are visible to other
users via `ps`. Store it once instead:

```
triagedy init          # hidden prompt; writes ~/.config/triagedy/env, mode 0600
triagedy doctor --backend jev
```

Resolution order: `--api-key` flag, then `$TYPESAFE_API_KEY`, then the stored
file. The flag exists for scripting only; prefer `init` or the environment.

## Usage

```
# assess alerts from stdin → JSONL decisions on stdout
triagedy run --backend ollama --model gemma4:e2b < alerts.jsonl

# pin the model in the environment instead of the command line
TRIAGEDY_MODEL=gemma4:e2b triagedy run --backend ollama < alerts.jsonl

# parallel assessments (4 in flight), output order still matches input order
triagedy run --backend ollama --model <name> --jobs 4 < alerts.jsonl

# files instead of pipes
triagedy run --backend mock --input alerts.jsonl --output decisions.jsonl

# check your backend before a real run
triagedy doctor --backend ollama --model gemma4:e2b
triagedy doctor --backend jev
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
