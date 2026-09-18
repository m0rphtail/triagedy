# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting on this repository:
**[Report a vulnerability](https://github.com/m0rphtail/triagedy/security/advisories/new)**

That flow is private between you and the maintainer. If you cannot use it,
open a minimal public issue that says only *"security issue — please enable a
private channel"* (no details) and a private thread will be set up.

Please include, where you can:

- a description of the issue and its impact
- the affected version or commit
- reproduction steps, ideally a minimal input file
- any suggested fix

## Scope

In scope — anything that breaks one of these guarantees:

| Guarantee | What to test |
|---|---|
| Alert data does not leak | the tool writes nothing outside the paths you name; no telemetry, no phone-home |
| Keys are never exposed | a key never appears in output, logs, error messages, or a command line; the stored file stays `0600` |
| Untrusted input is contained | malformed JSONL/XML is isolated per record; XML is parsed without DTD or entity resolution |
| The pipeline does not lie | a backend answer outside the allowed options or ranges is rejected, never silently defaulted |
| Routing cannot be talked into a downgrade | a malicious alert cannot cause `contain` or high-severity escalation to be suppressed |

Especially interesting: anything that makes the tool **silently under-react** to
a malicious alert. A false escalation costs an analyst a minute; a missed
containment costs an incident.

## Out of scope

- Vulnerabilities in TypeSafe's API, Ollama, or other upstream services — report
  those to the respective vendor.
- Model quality or accuracy on your alerts. That is a calibration question, not a
  vulnerability. See the README's Benchmarks section for how to measure it.
- Anything requiring a hostile process already running as the same user with
  read access to `~/.config/triagedy/env` — at that point the key is already
  yours.
- Denial of service through absurdly large local input files.

## Handling

- Best effort acknowledgement, usually within a few days.
- A fix lands with a test that would have caught it, whenever one can be written.
- Credit in the release notes if you want it.

## Supported versions

This project is pre-1.0 and moves on `main`. Fixes target the latest commit —
please reproduce against `main` before reporting.
