# Published Accuracy Benchmarks & Evaluation Methodology

This document publishes the empirical accuracy figures, statistical evaluation metrics, confusion matrices, and confidence calibration analysis for `triagedy`.

Following the evaluation methodology established in independent studies (e.g., *Southbridge Jev Observer Study*, 2026), evaluation requires:
1. **Held-out or real enterprise telemetry datasets** (not synthetic single-case prompts).
2. **Deterministic replay verification** across repeated runs.
3. **Rigorous statistical metric disclosure**: Accuracy, Precision, Recall/Sensitivity, Specificity, False Positive Rate, False Negative Rate, and F1 Score.
4. **Explicit confidence calibration disclosure** distinguishing calibrated probabilities from subjective model self-reports.

---

## 1. Real Enterprise Telemetry Benchmark

### Dataset: Splunk `attack_data` (Atomic Red Team Sysmon Telemetry)

- **Source**: Splunk Attack Data repository ([github.com/splunk/attack_data](https://github.com/splunk/attack_data)), recorded during an Atomic Red Team execution run simulating adversary command execution via obfuscated PowerShell (`powershell.exe -Exec bypass -enc ...`).
- **Input Scale**: 1,185 Sysmon XML Windows Event Log records converted using `triagedy convert --format sysmon-xml`.
- **Triage Corpus**: 64 process execution events (`EventID 1`) evaluated under production SOC Tier-1 filtering conditions.
- **Ground Truth**:
  - **Malicious Event (True Positive)**: 1 genuine attack execution (`win-dc-397.attackrange.local-33445`: `powershell.exe` spawned from `cmd.exe` executing an encoded payload).
  - **Benign Background Events (True Negatives)**: 63 routine operational process executions (Splunk universal forwarder monitoring binaries: `splunk-netmon.exe`, `splunk-powershell.exe`, `splunk-regmon.exe`, `splunk-admon.exe`, `splunk-winprintmon.exe`).
- **Adversarial Noise Ratio**: **63:1** (63 benign events for every 1 genuine threat).

### Results & Metrics Table

| Metric | Formula | Score | Notes |
|---|---|---|---|
| **Accuracy** | $(TP + TN) / Total$ | **100.0%** (64 / 64) | Zero misclassifications across entire telemetry stream. |
| **Precision (PPV)** | $TP / (TP + FP)$ | **100.0%** (1.000) | 1 alert escalated; exactly 1 true attack present. |
| **Recall / Sensitivity (TPR)** | $TP / (TP + FN)$ | **100.0%** (1.000) | Single adversary execution successfully caught and escalated. |
| **Specificity (TNR)** | $TN / (TN + FP)$ | **100.0%** (1.000) | All 63 benign background processes safely closed. |
| **False Positive Rate (Fall-out)** | $FP / (FP + TN)$ | **0.0%** (0.000) | Zero benign events misclassified as attacks. |
| **False Negative Rate (Miss Rate)** | $FN / (FN + TP)$ | **0.0%** (0.000) | Zero malicious attacks missed or suppressed. |
| **F1 Score** | $2 \cdot \frac{Precision \cdot Recall}{Precision + Recall}$ | **1.000** | Optimal balance of precision and recall. |
| **Noise Suppression Ratio** | $TN : TP$ | **63:1** | Reduced analyst alert load by 98.4% without alert leakage. |
| **Total Ingestion & Triage Time** | End-to-end runtime | **5.1 s** | 64 events buffered; ~79.7 ms/alert throughput. |

### Real Telemetry Confusion Matrix

```
                        Actual Attack         Actual Benign
                      ┌─────────────────────┬─────────────────────┐
Predicted Escalate    │   TP = 1            │   FP = 0            │
                      ├─────────────────────┼─────────────────────┤
Predicted Close       │   FN = 0            │   TN = 63           │
                      └─────────────────────┴─────────────────────┘
```

The single genuine attack event ranked **#1 of 64 by severity score** (`severity = 2.01`, `disposition = escalate`, `attack_class = execution`, `confidence = 1.0`). All 63 background events were routed to `action = close` with false-positive probabilities between `0.67` and `0.89`, satisfying the policy's false-positive screening gate.

---

## 2. Multi-Disposition Validation Benchmark

### Dataset: Synthetic Multi-Triage Corpus (8 Archetypal Alerts)

To validate routing accuracy across all four triage actions (`close`, `investigate`, `escalate`, `contain`), an archetypal suite was constructed representing common enterprise detection signatures and edge cases:

1. **A-1001**: Office spawns encoded PowerShell (Sigma rule `sigma_office_shell`) → Expected: `escalate`
2. **A-1002**: Rundll32 unusual argument from Temp path (Sigma rule `sigma_rundll32_temp`) → Expected: `investigate`
3. **A-1003**: LSASS memory handle opened by downloaded executable (`edr_lsass_handle`) → Expected: `escalate`
4. **A-1004**: Scheduled task created via GPO maintenance script with change ticket (`CR-4471`) → Expected: `close`
5. **A-1005**: External perimeter port scan matching registered vulnerability scanner (`asset_registry`) → Expected: `close`
6. **A-1006**: RDP login success from TOR exit node after repeated failures (`win_rdp_bruteforce`) → Expected: `contain`
7. **A-1007**: 20 GB compressed database archive staged and transferred outbound (`netflow_dlp`) → Expected: `investigate`
8. **A-1008**: Local administrator account added with no change ticket (`change_audit_localgroup`) → Expected: `investigate`

### Results: Jev vs. Local Fallback Model

| Alert ID | Target Triage Action | Jev (`jev-latest`) Action | Jev Confidence | Local Fallback (`gemma4:e2b`) Action | Local Confidence |
|---|---|---|---|---|---|
| **A-1001** | `escalate` | `escalate` ✅ | 0.92 (calibrated) | `investigate` ⚠️ | 0.85 (uncalibrated) |
| **A-1002** | `investigate` | `investigate` ✅ | 0.36 (review req) | `investigate` ✅ | 0.70 (uncalibrated) |
| **A-1003** | `escalate` | `escalate` ✅ | 0.49 (review req) | `investigate` ⚠️ | 0.80 (uncalibrated) |
| **A-1004** | `close` | `close` ✅ | 0.97 (calibrated) | `close` ✅ | 0.90 (uncalibrated) |
| **A-1005** | `close` | `close` ✅ | 0.87 (calibrated) | `close` ✅ | 0.92 (uncalibrated) |
| **A-1006** | `contain` | `contain` ✅ | 0.46 (review req) | `investigate` ⚠️ | 0.75 (uncalibrated) |
| **A-1007** | `investigate` | `investigate` ✅ | 0.68 (calibrated) | `investigate` ✅ | 0.65 (uncalibrated) |
| **A-1008** | `investigate` | `investigate` ✅ | 0.97 (calibrated) | `investigate` ✅ | 0.88 (uncalibrated) |

### Summary Statistics Comparison

| Metric | TypeSafe Jev (`jev-latest`) | Local Fallback (`gemma4:e2b`, CPU) |
|---|---|---|
| **Exact Disposition Accuracy** | **8 / 8 (100.0%)** | **6 / 8 (75.0%)** |
| **Dangerous Misclassifications (False Dismissal)** | **0 / 8 (0.0%)** | **0 / 8 (0.0%)** |
| **Conservative Deviations (`investigate`)** | 0 | 2 (diverted to analyst review) |
| **Run-to-Run Drift** | **0 drift** across repeated runs (confidence delta ≤ 0.04) | Variable (temperature-dependent) |
| **Total Run Latency** | **1.4 s** (175 ms / alert) | **490 s** (~61 s / alert on RPi5) |
| **Memory Footprint** | Lightweight client (~12 MB resident) | ~6.8 GB resident model |

Both models maintained **0.0% dangerous errors** (no malicious alert was dismissed as benign). The local model's deviations were strictly conservative (flagging for manual analyst investigation rather than closing).

---

## 3. Confidence Calibration Analysis

A critical finding in production security AI is the distinction between **calibrated probabilities** and **uncalibrated self-reported confidence**.

### The Calibration Problem in LLMs
When prompted with:
> *"How confident are you in this answer? (0.0 to 1.0)"*

standard autoregressive language models (GPT-4, Claude, Gemma, Llama) output subjective, uncalibrated tokens. Extensive machine learning literature demonstrates that:
1. LLMs exhibit severe **overconfidence** on incorrect answers (frequently answering with 0.90+ confidence when hallucinating).
2. Self-reported numbers do not follow empirical probability: an alert assigned "0.80 confidence" by an LLM is **not** correct 80% of the time.

### How TypeSafe Jev Solves This
TypeSafe Jev (System One) is trained to output **empirically calibrated probabilities**:
- When Jev returns `0.85`, historical empirical observations indicate that the probability of true classification matches that frequency.
- Jev probabilities satisfy scoring rule calibration (Brier score alignment), meaning downstream code can set mathematical risk thresholds (e.g. `fp >= 0.50` for auto-close).

### How `triagedy` Fixes the Fallback Path
To protect downstream automated systems when using the OpenAI-compatible fallback:
1. **Explicit Calibration Metadata**: Every output JSON record emits `confidence_calibrated: bool`:
   ```json
   {
     "backend": "jev",
     "confidence_calibrated": true,
     "decision": { "disposition_confidence": 0.92 }
   }
   ```
   For the OpenAI fallback or mock backend, `confidence_calibrated` is emitted as `false`.
2. **Deterministic Safety Latches in Policy**: In `src/policy.rs`:
   - If `confidence_calibrated == false`, policy automatically attaches an advisory note: `"uncalibrated confidence: model self-report, human review advised for automated actions"`.
   - Any high-impact action (`Action::Contain` or `Action::Escalate` at severity ≥ 2.0) derived from an uncalibrated backend is automatically flagged with `review_required: true`. This prevents an automated SOAR or EDR tool from isolating critical production servers based on an uncalibrated LLM self-report.
