# Validated Security Operations Workflow

`triagedy` operationalizes alert triage as a validated SOC Tier-1 workflow directly grounded in industry incident response standards:

- **NIST SP 800-61 Rev. 2** (*Computer Security Incident Handling Guide*): Section 3.2 "Detection and Analysis", Section 3.2.6 "Incident Prioritization", and Section 3.3.1 "Containment Strategy".
- **MITRE ATT&CK Enterprise Matrix v15+**: Primary tactic progression taxonomy (TA0002, TA0006, TA0003, TA0008, TA0010).
- **SANS Incident Handler Playbooks**: Tier-1 triage verification gates, auto-closure thresholds, and Tier-2/IR escalation handoffs.

---

## 1. Why a Decomposed Rubric Beats Monolithic LLM Prompts

Conventional AI triage prompts ask an LLM for a free-text verdict or an ungrounded severity label. Empirical security benchmarks (e.g., *jev-phishing-bench*, Southbridge 2026) show that monolithic LLM verdicts have high variance and uncalibrated confidence.

In contrast, `triagedy` decomposes alert triage into **five orthogonal, typed questions** matching formal SOC decision gates. Models judge bounded dimensions; deterministic code in `src/policy.rs` enforces operational policy:

```
                  ┌─────────────────────────────────────────────────┐
                  │                 Incoming Alert                  │
                  │   (Elastic ECS, CrowdStrike FDR, Sysmon XML)    │
                  └───────────────────────┬─────────────────────────┘
                                          │
                  ┌───────────────────────▼─────────────────────────┐
                  │          Bounded Judgment Engine                │
                  │       (TypeSafe Jev / System One)               │
                  └───────┬───────┬───────┬───────┬─────────┬───────┘
                          │       │       │       │         │
             ┌────────────┘       │       │       │         └──────────┐
             ▼                    ▼       ▼       ▼                    ▼
       1. Disposition        2. Severity 3. FP  4. Escalate       5. Technique
      (NIST §3.2 Action)     (NIST §3.2.6) (Gate)  (Urgency)      (MITRE Tactic)
             │                    │       │       │                    │
             └────────────┬───────┴───────┴───────┴────────────────────┘
                          │
                  ┌───────▼─────────────────────────────────────────┐
                  │       Deterministic Policy Engine (`policy.rs`) │
                  │       - False-positive screening gate           │
                  │       - Containment non-downgrade invariant     │
                  │       - Severity escalation threshold           │
                  │       - Uncalibrated confidence safety latch    │
                  └───────┬───────────────┬─────────────────┬───────┘
                          │               │                 │
             ┌────────────┘               ▼                 └──────────┐
             ▼                                                         ▼
        AUTO-CLOSE                 ANALYST QUEUE               CONTAIN / ESCALATE
    (Sanctioned/Benign)        (Enrichment / Context)         (Active Compromise)
```

---

## 2. Formal Mapping of the Rubric to Security Standards

### Question 1: Triage Disposition (`disposition`)
*Type: Choice (`close` | `investigate` | `escalate` | `contain`)*

Directly operationalizes **NIST SP 800-61r2 §3.2.2** (Incident Declaration & Scoping):

| Disposition | NIST SP 800-61r2 Lifecycle Stage | SOC Operational Action |
|---|---|---|
| `close` | Pre-incident baseline / False Positive (§3.2.4) | Resolve alert; no human intervention needed; document rationale. |
| `investigate` | Preliminary Analysis / Scoping (§3.2.5) | Route to Tier-1 analyst triage queue with extracted entities and context. |
| `escalate` | Incident Declaration / P1/P2 (§3.2.6) | Dispatch immediately to Tier-2 / Computer Security Incident Response Team (CSIRT). |
| `contain` | Active Containment Trigger (§3.3.1) | Immediate containment priority: host isolation, token revocation, account disablement. |

### Question 2: Incident Severity (`severity`)
*Type: Score (0.0 to 3.0)*

Directly operationalizes **NIST SP 800-61r2 §3.2.6** (*Incident Prioritization*), evaluating functional impact, information impact, and recoverability effort:

| Level | Range | Functional & Information Impact | Standard SOC SLA |
|---|---|---|---|
| **0. Informational** | 0.0 – 0.5 | No functional impact; no sensitive data affected. Routine telemetry. | No SLA / Log only |
| **1. Low** | 0.5 – 1.5 | Minimal functional impact; non-critical system; explainable anomaly. | 24–48 hours |
| **2. High** | 1.5 – 2.5 | Core service degraded; privileged account or sensitive data targeted. | 15–30 minutes |
| **3. Critical** | 2.5 – 3.0 | Catastrophic impact; active exfiltration, domain compromise, ransomware. | Immediate (<5 min) |

### Question 3: False-Positive Probability (`false_positive_probability`)
*Type: Noul (0.0 to 1.0 probability)*

Operationalizes the **SOC Verification Gate**. An alert must prove it is benign through positive evidence (sanctioned maintenance window, vulnerability scanner registration, signed administrative script) rather than lack of attacker skill.

- In `policy.rs`, a `close` verdict is rejected unless `fp >= 0.5` (or `fp >= 0.7` if `severity >= 2.0`).

### Question 4: Incident Response Escalation Urgency (`requires_escalation`)
*Type: Noul (0.0 to 1.0 probability)*

Operationalizes **SANS Incident Handler Escalation Thresholds**. Independent of disposition, this measures whether the telemetry indicates active attacker dwell time requiring urgent human handoff.

- In `policy.rs`, if `investigate` was selected but `requires_escalation >= 0.9` AND `severity >= 2.0`, code automatically promotes the action to `escalate`.

### Question 5: Threat Technique Category (`attack_class`)
*Type: Choice (`none` | `execution` | `credential_access` | `persistence` | `lateral_movement` | `exfiltration`)*

Operationalizes **MITRE ATT&CK Enterprise Tactics**. These categories represent the primary kill-chain progression tactics critical for fast Tier-1 triage:

| Category | MITRE ATT&CK Tactic | Detection Focus |
|---|---|---|
| `none` | N/A | Benign administrative, operational, or test activity. |
| `execution` | TA0002 | Script engines (PowerShell, bash, cmd), living-off-the-land binaries (LOLBins). |
| `credential_access` | TA0006 | LSASS dumping, SAM registry access, brute force, Kerberoasting. |
| `persistence` | TA0003 | Scheduled tasks, service creation, run keys, backdoor user creation. |
| `lateral_movement` | TA0008 | Remote service execution, WinRM, WMI, SMB, RDP compromise. |
| `exfiltration` | TA0010 | Archive staging (7z, zip), outbound encrypted transfers, egress volume anomaly. |

### Context Dimension: Alert Deduplication (`duplicate_of_recent`)
*Type: Noul (0.0 to 1.0 probability, active with `--context`)*

Operationalizes **SOC SLA Event Grouping and Fatigue Mitigation**:
- When `--context <previous-run.jsonl>` is provided, the last 20 triage decisions accompany the alert.
- If `duplicate_probability >= 0.8` on an alert with `severity < 2.0`, an `escalate` action can be downgraded to `investigate` to prevent ticket flooding.
- **Safety Invariant**: Containment actions are **never** downgraded, and high-severity incidents (`severity >= 2.0`) are never suppressed.

---

## 3. Operational Policy Invariants

In `src/policy.rs`, human analysts define policy invariants in ordinary Rust code:

1. **Containment Invariant**: `Action::Contain` is non-negotiable. No duplicate threshold or suppression rule can downgrade or suppress an active containment verdict.
2. **False-Positive Gate Invariant**: A `close` disposition can never execute on an alert unless the false-positive probability exceeds the safety threshold:
   - Severity < 2.0: Requires `fp >= 0.50`
   - Severity ≥ 2.0: Requires `fp >= 0.70`
   - Failure to meet the gate automatically diverts the action to `Action::Investigate`.
3. **Escalation Promotion Invariant**: High-severity alerts (`severity >= 2.0`) with high escalation urgency (`requires_escalation >= 0.90`) are automatically upgraded to `Action::Escalate`.
4. **Calibration Safety Invariant**: When running against uncalibrated backends (such as the OpenAI-compatible fallback), self-reported confidence numbers are uncalibrated. High-impact actions (`Action::Contain` or `Action::Escalate` at severity ≥ 2.0) automatically enforce `review_required: true` and record an explicit advisory note.

---

## 4. SOC Pipeline Integration

`triagedy` functions as a standard UNIX filter in enterprise security pipelines:

```bash
# Production SIEM ingestion (Elastic ECS / CrowdStrike FDR / Sysmon)
curl -s "https://siem.internal/api/v1/alerts?since=1h" \
  | triagedy run --jobs 8 \
  | jq -c 'select(.action == "contain" or .action == "escalate")' \
  | ./scripts/dispatch_incident_pager.sh
```

### Webhook & SOAR Routing Reference

| Action | `review_required` | Downstream Automation | Target System |
|---|---|---|---|
| `close` | `false` | Auto-resolve ticket with audit rationale attached | SIEM / Jira / ServiceNow |
| `close` | `true` | Low-priority review queue (FP gate holdback) | Tier-1 Analyst Queue |
| `investigate` | `false` | Standard investigation ticket with parsed IOCs | Tier-1 Analyst Queue |
| `investigate` | `true` | High-priority investigation ticket (uncertain model) | Senior Analyst Queue |
| `escalate` | `false` | Page on-call incident responder; create P1 incident | PagerDuty / Opsgenie / CSIRT |
| `escalate` | `true` | Senior analyst verification queue before P1 paging | On-call IR Triage |
| `contain` | `false` (Jev) | Automated host isolation / credential revocation | EDR (CrowdStrike, Defender, SentinelOne) |
| `contain` | `true` (OpenAI) | Prompt analyst for 1-click containment authorization | SOAR Authorization Modal |
