# Contributing to triagedy

Thanks for wanting to help. This is a small, focused tool — the best
contributions keep it small.

## The one rule

**Alert data never enters this repository.** Not real telemetry, not "just a
small sample", not in a test fixture, not in a README example. Corpora live
outside the repo (`fixtures/` is gitignored for exactly this reason). If you
need data to test something, build a synthetic alert from scratch with invented
hostnames, users, and RFC 5737 documentation IPs (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`).

Synthetic alerts that *describe* an attack shape are fine. Anything derived from
a real environment is not.

## Getting started

```bash
git clone https://github.com/m0rphtail/triagedy
cd triagedy
cargo test                # 71 tests, no network, no API key needed
cargo build --release
```

You do **not** need an API key to develop. Every test runs against `mock` or a
local wiremock server.

## The gate

Every commit must pass all four. CI runs exactly this:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

`cargo clippy` must print no warnings — `-D warnings` turns each one into a
failure. If you are unsure, run the four commands in order and read the output.

## Workflow

1. **Open an issue first** for anything larger than a bug fix — a new backend, a
   change to the policy thresholds, a new input format. It is much cheaper to
   agree on the approach before you write it.
2. Branch: `git checkout -b feat/short-description`.
3. **Write the test first.** Add it, run it, watch it fail for the right reason,
   then implement. Every behaviour change needs a test that would catch a
   regression.
4. Keep commits small and one-purpose. Imperative subject line, body explains
   *why* rather than restating the diff.
5. Run the gate, push, open a PR.

## What a good change looks like

- **Tests prove behaviour, not implementation.** A test that asserts the shape of
  the output record survives refactors; a test that asserts a private function
  was called does not.
- **Safety-relevant changes are conservative by default.** The routing policy
  exists to decide when *not* to act. A change that makes the tool act more
  aggressively on malicious input needs a strong argument, and the tests in
  `src/policy.rs` will hold you to it.
- **No new dependencies without a reason in the PR description.** The tool is
  deliberately one binary with a small dependency set so it deploys anywhere.
- **Comments explain why.** The code says what it does.

## Project layout

| Path | What lives there |
|---|---|
| `src/alert.rs` | JSONL parsing; the vendor field-key maps (Sysmon, ECS, CrowdStrike FDR) |
| `src/backends/` | One `assess()` per transport: `jev`, `openai`, `mock` |
| `src/questions.rs` | The five questions — as TypeSafe questions, as a chat prompt, as a JSON schema |
| `src/decision.rs` | Validation: raw answers become a typed `Decision` or an error |
| `src/policy.rs` | Routing thresholds. Plain code, unit-tested |
| `src/engine.rs` | The order-preserving JSONL pipeline |
| `src/context.rs` | Recent-activity parsing for `--context` |
| `src/convert.rs` | `triagedy convert` — XML to JSONL |
| `tests/cli.rs` | End-to-end tests that spawn the real binary |

## Adding a backend

The whole contract is one method:

```rust
pub async fn assess(
    &self,
    alert: &Alert,
    context: Option<&TriageContext>,
) -> Result<RawAnswers, String>
```

Add a variant in `src/backends/mod.rs`, a module beside the others, and an arm
in the dispatch. Return `RawAnswers` — validation and routing happen downstream,
so a backend that returns bad options fails loudly rather than corrupting a
decision.

## Security contributions

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability —
use the private advisory flow.

## License

By contributing you agree your work is licensed under the MIT license, the same
as the project.
