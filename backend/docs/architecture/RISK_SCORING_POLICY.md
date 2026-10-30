# AEGIS Risk Scoring & Decision Policy
**Version**: 5.0.0  
**Status**: Authoritative Reference  
**Applicability**: AEGIS Analysis Pipeline (`app.services.risk_engine`)

---

## 1. Overview & Architecture Principles

AEGIS employs a **unified, deterministic, explainable risk-scoring and decision framework**. The engine synthesizes multi-source cyber threat intelligence into a normalized score, categorical verdict, and security action.

### Core Principles
1. **Deterministic Execution**: Given identical intelligence evidence and policy version, the engine strictly produces identical scores, verdicts, actions, and explanations.
2. **Threat Intelligence Supremacy**: Authoritative confirmed threat indicators (Google Safe Browsing or consensus VirusTotal malicious detections) immediately trigger high-priority `CRITICAL` / `BLOCK` overrides. No heuristic prediction (ML), registration age (RDAP), or advisory recommendation (AI) can downgrade a confirmed threat.
3. **No False Safe Verdicts**: A score of 0 does not imply `SAFE`. Declaring a URL `SAFE` (`ALLOW`) requires verified, clean evidence across all independent core detection systems. If evidence is missing, unconfigured, pending, or failed, the system conservatively defaults to `INSUFFICIENT_EVIDENCE`.
4. **Separation of Risk & Confidence**: Risk score (severity of threat indicators, 0–100) is evaluated independently from confidence / completeness (quality and coverage of evidence, 0.0–1.0).
5. **Advisory AI Boundaries**: Hybrid AI (Local Ollama / Cloud Claude) functions strictly as an advisory explanation layer. AI output is never permitted to independently determine or alter final risk scores or verdicts.

---

## 2. Risk Score Normalization & Severity Bands

Risk scores are normalized integers on a scale of `0` to `100`:

| Risk Score Band | Risk Classification | Action Trigger | Typical Evidence State |
|---|---|---|---|
| **0 – 19** | **Low Risk** | `ALLOW` (if verified) / `WARN` | Verified legitimate domain, clean security feeds, mature domain age. |
| **20 – 39** | **Limited Risk** | `WARN` | Minor heuristics (e.g. recent domain age 30–90 days, or isolated unverified flag). |
| **40 – 59** | **Moderate Risk** | `WARN` | High-confidence ML phishing prediction, very new domain (<14 days), or single suspicious feed detection. |
| **60 – 79** | **High Risk** | `BLOCK` | Corroborating suspicious indicators (e.g., ML phishing + new domain + typosquatting match). |
| **80 – 100** | **Critical Risk** | `BLOCK` | Confirmed malware/phishing match in Google Safe Browsing or multi-engine VirusTotal consensus. |

---

## 3. Evidence Sources & Weighting Methodology

### A. Google Safe Browsing (Lookup API v4)
- **Role**: Authoritative External Threat Feed (Tier 1 Priority).
- **Rule**: If `status == "completed"` and `threat_detected is True`:
  - **Override Trigger**: Score forced to **`100`**, Verdict forced to **`CRITICAL`**, Action forced to **`BLOCK`**.
  - **Reason**: `"Google Safe Browsing confirmed a threat."`
- **Clean Response**: `threat_detected is False` contributes `+0` risk and acts as a required prerequisite for `SAFE`.
- **Unavailable/Failed**: Does not increase risk, but prevents declaring `SAFE`.

### B. VirusTotal (API v3)
- **Role**: Multi-Engine Consensus Threat Intelligence (Tier 1 Priority).
- **Rule**:
  - `malicious >= 2` (High-Confidence Consensus):
    - **Override Trigger**: Score forced to **`90`** (if 2–4 detections), **`95`** (if 5–9 detections), or **`100`** (if >= 10 detections).
    - **Verdict**: Forced to **`CRITICAL`**, Action forced to **`BLOCK`**.
    - **Reason**: `"Multiple VirusTotal engines reported malicious activity."`
  - `malicious == 1` (Isolated Detection):
    - **Accumulated Weight**: **`+25`** risk points.
  - `suspicious > 0`:
    - **Accumulated Weight**: **`+min(suspicious * 5, 15)`** risk points (max 15 points).
  - `malicious == 0 and suspicious == 0`:
    - Contributes `+0` risk and acts as a prerequisite for `SAFE`.
  - Pending/Unavailable/Failed:
    - Does not add risk points, but prevents declaring `SAFE`.

### C. Machine Learning Classifier (PhishOFE Random Forest)
- **Role**: Lexical and Structural URL Feature Heuristics.
- **Rule**:
  - **Calibrated Piecewise Probability Formulation**:
    - For $P < 0.50$ (or `prediction == "legitimate"`):
      - **`score_delta = 0`** points. Low phishing probability never adds risk points.
      - Recorded as benign supporting factor if $0.0 \le P < 0.50$.
    - For $P \ge 0.50$ (and `prediction == "phishing"`):
      - **`score_delta = round(30 + (P - 0.50) * 40)`** points (bounded to $[30, 50]$).
      - Smoothly scales from **30 points at $P = 0.50$** (entry to `SUSPICIOUS` band) to **50 points at $P = 1.00$**.
      - Every $0.05$ increase in probability adds $2$ risk points.
  - **Boundaries & Supremacy**:
    - **ML alone never triggers `CRITICAL`**: Max ML score is 50 points, strictly below the 70-point `CRITICAL` threshold.
    - **ML alone never triggers `SAFE`**: A benign prediction contributes 0 points, but `SAFE` requires verification across GSB, VT, and completeness $\ge 0.75$.
  - **Invalid, NaN, and Infinite Probabilities**:
    - Sanitized and omitted from scoring ($+0$ points).
    - Recorded in `contradictory_factors` and explicitly disqualifies the scan from achieving `SAFE`, safely defaulting to `INSUFFICIENT_EVIDENCE`.
  - **Known Bare-Domain Bias Mitigation**:
    - When ML predicts phishing on an established bare domain due to lack of subdomains and path depth, but GSB and VT are clean, the contradiction is recorded and score remains capped at 50 (`SUSPICIOUS`/`WARN`), preventing unjustified blocking while awaiting domain reputation signals.

### D. RDAP Domain Registration Intelligence
- **Role**: Temporal and Registrar Context.
- **Rule**:
  - `registered is False`: **`+15`** risk points (unregistered or un-delegated domain).
  - `domain_age_days < 14`: **`+15`** risk points (newly registered zero-day campaign domain).
  - `domain_age_days < 30`: **`+10`** risk points (young domain).
  - `domain_age_days < 90`: **`+5`** risk points (recent domain).
  - `domain_age_days >= 365`: **`+0`** risk points (recorded as benign supporting factor).
  - **Unsupported TLDs**: Authoritative absence due to an unsupported TLD does **NOT** count as an unregistered domain and contributes **`+0`** risk points.
  - **Network Timeouts & Failures**: RDAP timeouts (`status: "unavailable"`) or network connection errors (`status: "failed"`) contribute **`+0`** risk points and are recorded in `missing_factors`.
  - **Missing Registration Dates**: If the registry omits creation events, `domain_age_days` remains unknown and contributes **`+0`** risk points.
  - **Threshold Boundaries**: Domain age alone never triggers `CRITICAL` or `SUSPICIOUS` (max 15 pts < threshold 30). Established domain age never overrides confirmed threats.

### E. DomainShield (Typosquatting & Brand Impersonation)
- **Role**: Multi-technique Lexical and Structural Brand Impersonation Defense.
- **Status in Phase 5**: Fully active and integrated.
- **Rule**:
  - `status == "completed"` and `impersonation_detected is True`:
    - **Accumulated Weight**: **`+15`** risk points.
    - **Severity Floor**: Confirmed impersonation enforces a minimum risk score of **`30`** (`SUSPICIOUS` / `WARN`).
    - **Disqualification of SAFE**: A confirmed brand impersonation strictly prohibits a `SAFE` verdict regardless of other clean signals.
    - **Techniques Evaluated**: Damerau-Levenshtein mutations (substitution, insertion, deletion, transposition), Unicode homoglyphs and confusables, IDN Punycode decoding, subdomain brand injection, and brand + security keyword composition.
  - `status == "completed"` and `impersonation_detected is False`:
    - Contributes **`+0`** risk points and acts as a verified clean signal prerequisite for `SAFE`.
  - `status in ("failed", "unavailable", "not_run")`:
    - Contributes **`+0`** risk points, recorded in `missing_factors`, and conservatively prevents declaring `SAFE`.
  - **Supremacy & Isolation**: DomainShield alone never declares `CRITICAL` or `SAFE`. DomainShield points never override Google Safe Browsing or VirusTotal confirmed threats.

### F. Hybrid AI (Local Ollama / Cloud Claude)
- **Role**: Advisory Explanation & Contextual Threat Correlation.
- **Rule**:
  - AI recommendations (`ALLOW`, `WARN`, `BLOCK`) **never modify numerical risk score**.
  - AI confidence score is advisory and not treated as a statistical certainty.
  - Discrepancies between AI advice and deterministic intelligence are logged in `contradictory_factors`.

---

## 4. Final Verdict and Action Mapping

```
                                [Collect Evidence Checks]
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │ Is Google Threat Detected OR VT Malicious >= 2?│
                    └───────────────────────┬───────────────────────┘
                                           YES                      NO
                                            │                        │
                                            ▼                        ▼
                                    [CRITICAL / BLOCK]     [Accumulate Provider Risk]
                                     (Score: 90 - 100)      (ML + VT + RDAP + Shield)
                                                                     │
                                                                     ▼
                                                      ┌──────────────────────────────┐
                                                      │ Total Accumulated Score >= 70?│
                                                      └──────────────┬───────────────┘
                                                                    YES              NO
                                                                     │                │
                                                                     ▼                ▼
                                                             [CRITICAL / BLOCK] ┌───────────────────────────┐
                                                             (Score: 70 - 100)  │ Total Score >= 30?         │
                                                                                └─────────────┬─────────────┘
                                                                                             YES            NO
                                                                                              │              │
                                                                                              ▼              ▼
                                                                                     [SUSPICIOUS / WARN] [Check Safe Criteria]
                                                                                      (Score: 30 - 69)      │
                                                                                                            │
                                                                               ┌────────────────────────────┴───────────────────────────┐
                                                                              YES (All Core Clean)                                     NO (Missing/Failed)
                                                                               │                                                         │
                                                                               ▼                                                         ▼
                                                                        [SAFE / ALLOW]                                        [INSUFFICIENT_EVIDENCE / WARN]
                                                                        (Score: 0 - 29)                                        (Score: 0 - 29)
```

### Safety Criteria for `SAFE` Verdict
To be granted a `SAFE` verdict with `ALLOW` action, **all** conditions must hold:
1. `google_safe_browsing.status == "completed"` and `threat_detected is False`.
2. `ml.status == "completed"` and `prediction == "legitimate"` and `phishing_probability < 0.50`.
3. `virustotal.status == "completed"` and `malicious == 0` and `suspicious == 0`.
4. `evidence_completeness >= 0.75` (at least 3 of 4 core providers successfully completed).
5. `domain_shield.status == "completed"` and `impersonation_detected is False` (if `domain_shield` is present in checks; `failed` or `unavailable` DomainShield strictly prevents `SAFE`).

If any condition fails, the verdict defaults to **`INSUFFICIENT_EVIDENCE`** with action **`WARN`**.

---

## 5. Evidence Completeness & Confidence Classification

AEGIS separates **risk severity** from **evidence certainty**.

### Core Providers Monitored
- `ml`: Random Forest classification
- `google_safe_browsing`: Threat lookup
- `virustotal`: Multi-engine scan analysis
- `rdap`: Registration age and registry delegation

### Metric Definitions
- **`evidence_completeness`**: $\text{Completeness} = \frac{\text{Completed Core Providers}}{\text{Total Core Providers (4)}}$ (float between `0.0` and `1.0`).
- **`confidence_level`**:
  - **`"HIGH"`**:
    - Confirmed threat override triggered (authoritative high confidence), OR
    - `evidence_completeness == 1.0` (all 4 core providers completed) and no major contradictory indicators.
  - **`"MEDIUM"`**:
    - `evidence_completeness >= 0.75` (3 of 4 providers completed), OR
    - Minor contradictory indicators present (e.g., bare domain ML false positive with clean threat intelligence).
  - **`"LOW"`**:
    - `evidence_completeness < 0.75` (<= 2 providers completed), OR
    - Key threat intelligence providers unavailable or failed.

---

## 6. Deterministic Explanation Schema

The risk engine generates an explainable decision structure:

```json
{
  "summary": "Google Safe Browsing confirmed a threat.",
  "verdict": "CRITICAL",
  "risk_score": 100,
  "action": "BLOCK",
  "confidence_level": "HIGH",
  "evidence_completeness": 1.0,
  "supporting_factors": [
    "Google Safe Browsing confirmed a threat (MALWARE)."
  ],
  "benign_factors": [],
  "contradictory_factors": [
    "ML classifier predicted legitimate, but confirmed threat intelligence takes absolute precedence."
  ],
  "missing_factors": [],
  "scoring_policy_version": "4.0.0"
}
```

---

## 7. Known Limitations
1. **URL-Only ML**: The ML classifier analyzes lexical/structural patterns without rendering live DOM or executing JavaScript.
2. **Third-Party Rate Limits**: Free-tier Google Safe Browsing and VirusTotal APIs may trigger rate limits (`429`), causing providers to return `unavailable`. The engine correctly handles this by reverting to `INSUFFICIENT_EVIDENCE` rather than reporting false safety.
3. **RDAP Registry Variance**: Certain country-code TLDs (ccTLDs) do not support open RDAP query formats, yielding incomplete domain age data.
