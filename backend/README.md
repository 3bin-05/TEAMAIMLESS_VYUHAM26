# AEGIS — AI-Powered Phishing Detection and Browser Protection System

AEGIS is an enterprise-grade cyber-defense system engineered to detect phishing, credential harvesting, typosquatting, and zero-day malicious domains in real time. The backend is powered by FastAPI, SQLAlchemy, and SQLite, feeding multi-source intelligence verdicts to a React dashboard and Chrome browser extension.

---

## Architecture Overview

AEGIS operates a modular, decoupled domain architecture:
- **`app.api`**: REST routing, Pydantic validation, and OpenAPI documentation.
- **`app.core`**: Centralized Pydantic Settings, structured logging with URL parameter masking, and global exception handlers.
- **`app.db`**: SQLite database with SQLAlchemy ORM entities (`URLScan`, `DetectionResult`, `UserDecision`) and schema evolution routines.
- **`app.schemas`**: Pydantic v2 schemas enforcing strict verdict literals (`SAFE`, `SUSPICIOUS`, `CRITICAL`, `INSUFFICIENT_EVIDENCE`), bounded batch sizes (1–20), and response contracts.
- **`app.services`**:
  - **`analyzer.py`**: Central coordinator orchestrating concurrent threat analysis across all providers, applying timeouts and exception isolation, persisting provider evidence to SQLite, and computing deterministic risk verdicts.
  - **`ml_service.py`**: Random Forest inference service utilizing URL-only lexical/structural features derived from the PhishOFE dataset.
  - **`google_safe_browsing.py`**: Google Safe Browsing Lookup API (v4) client checking for malware, social engineering, and unwanted software threats.
  - **`virustotal_service.py`**: VirusTotal API v3 integration with submission, bounded status polling, and threat statistic aggregation.
  - **`rdap_service.py`**: Authoritative domain registration intelligence with IANA bootstrap routing, domain age calculation, and registrar extraction.
  - **`risk_engine.py`**: Deterministic risk scoring boundary preventing false SAFE verdicts on incomplete or unverified evidence.
- **`app.utils`**: URL normalization, domain extraction, and SSRF defense validation.

---

## Technology Stack

- **Language**: Python 3.12
- **Framework**: FastAPI 0.115+
- **ASGI Server**: Uvicorn
- **Machine Learning**: Scikit-Learn 1.6+, Pandas, NumPy, Joblib
- **Database**: SQLite with SQLAlchemy 2.0+
- **HTTP Client**: HTTPX (Async)
- **Testing**: Pytest & Pytest-Asyncio with TestClient

---

## Machine Learning & Datasets

### 1. Dataset Inspection
- **`data/PhishOFE.csv`**:
  - 101,061 unique URLs, 32 columns.
  - Class distribution: 51,570 legitimate (`0`), 49,491 phishing (`1`).
  - Label mapping verified: 24,135 overlapping verified phishing URLs in PhishTank map 100.0% to label `1`.
- **`data/PhishTank.csv`**:
  - 53,353 verified, active phishing records used as an independent zero-day evaluation benchmark.

### 2. Feature Extraction Methodology (Option B: URL-Only Model)
To eliminate latency, avoid dependency on dead/offline phishing servers, and guarantee zero SSRF vulnerability, AEGIS extracts 11 reproducible URL-only features:
1. `IsHTTPS`: 1 if protocol is HTTPS, 0 otherwise.
2. `IsDomainIP`: 1 if hostname is an IPv4 or IPv6 address.
3. `URLLength`: Total character length of URL.
4. `NoOfSubDomain`: Subdomain depth (`hostname.count('.') - 1`).
5. `NoOfDots`: Total dot count in URL.
6. `NoOfObfuscatedChar`: Total hyphen count in URL.
7. `NoOfEqual`: Total '=' characters.
8. `NoOfQmark`: Total '?' characters.
9. `NoOfAmp`: Total '&' characters.
10. `NoOfDigits`: Count of numeric digits.
11. `TLD_freq`: Frequency of top-level domain from training distribution.

Webpage-derived features (e.g. `HasTitle`, `HasPasswordField`) from the original PhishOFE dataset are intentionally omitted rather than filled with arbitrary zeros.

### 3. Model Training & Evaluation
To retrain or evaluate the model:
```powershell
.\.venv\Scripts\Activate.ps1
python ml/train_model.py
python ml/evaluate_model.py
```

**Evaluation Results (Domain-Grouped Holdout Split 80/20, Model v2.0 Calibrated)**:
- **Accuracy**: **98.18%** (v1.0 was 96.48%)
- **Precision (Phishing)**: **99.59%** (v1.0 was 96.88%)
- **Recall (Phishing)**: **96.30%** (v1.0 was 95.17%)
- **F1-Score**: **97.92%** (v1.0 was 96.02%)
- **ROC-AUC**: **0.9976** (v1.0 was 0.9921)
- **PR-AUC**: **0.9976** (v1.0 was 0.9918)
- **False Positive Rate**: **0.32%** (v1.0 was 2.46% — an 87% reduction in false positives)
- **Independent Legitimate Benchmark**: Bare domains (`linkedin.com`, `google.com`, `github.com`, `microsoft.com`, `apple.com`, `amazon.com`, `python.org`, `wikipedia.org`, `cloudflare.com`, `stackoverflow.com`): **100% legitimate** with < 0.04 phishing probability.
- **PhishTank External Holdout Detection Rate**: **87.40%** (verified on 500 independent external verified phishing URLs)

The trained calibrated model artifact is stored at:
`ml/model.joblib` with metadata at `ml/model_metadata.json` (baseline archived at `ml/model_v1_baseline.joblib`).

---

## External Detection Services Setup

### Google Safe Browsing Setup
1. Obtain an API key from the [Google Cloud Console](https://console.cloud.google.com/) for Safe Browsing APIs.
2. Set in `.env`:
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
   ```

### VirusTotal Setup
1. Register for an API key at [VirusTotal](https://www.virustotal.com/).
2. Set in `.env`:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ```

### RDAP Domain Intelligence
- Uses authoritative IANA RDAP DNS bootstrap routing (`.com`, `.net`, `.org`, `.io`, `.in`, `.de`, etc.).
- Computes `domain_age_days` from registration timestamp.
- No API key required.

---

## Environment Configuration

Configuration variables in `.env` (copy from `.env.example`):
```env
APP_NAME=AEGIS
APP_ENV=development
DEBUG=true
API_PREFIX=/api/v1
DATABASE_URL=sqlite:///./data/aegis.db
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
LOG_LEVEL=INFO

ML_MODEL_PATH=ml/model.joblib
REQUEST_TIMEOUT=8
RDAP_BASE_URL=https://rdap.org/domain/

# Optional External API Keys & AI Configuration
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022

# Phase 3: Hybrid AI Engine Settings
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=
AEGIS_AI_MODE=AUTO
AEGIS_CLOUD_AI_ENABLED=false
AEGIS_AI_TIMEOUT_SECONDS=20
AEGIS_AI_HEALTH_CHECK_INTERVAL=300
```

---

## Phase 3: Hybrid AI Intelligence Engine

AEGIS implements a privacy-first, hybrid AI intelligence architecture designed to act as an explanatory and threat correlation layer without compromising security or latency.

### 1. Hybrid AI Routing Architecture
The Hybrid AI Router (`app/services/ai/ai_router.py`) coordinates between local inference (Ollama) and cloud AI (Anthropic Claude):
- **Advisory Role Only**: The AI engine provides rich security context, evidence synthesis, and actionable recommendations. The **deterministic risk engine remains the sole authority** for threat verdicts (`SAFE`, `SUSPICIOUS`, `CRITICAL`, `INSUFFICIENT_EVIDENCE`). AI can never downgrade confirmed malicious verdicts or invent threat findings.
- **Privacy & Cloud Consent**: Cloud processing is strictly gated behind `AEGIS_CLOUD_AI_ENABLED=true` in backend configuration **and** explicit request-level consent (`allow_cloud_ai: true`). If cloud consent is absent, scan data is never sent to Anthropic.
- **Offline Intelligence vs. Network Services**: While local Ollama inference operates completely offline, live threat intelligence providers (Google Safe Browsing, VirusTotal, RDAP) require active internet connectivity.
- **Prompt Injection Defense**: Untrusted URLs, domain names, and external intelligence payloads are strictly isolated inside delimited JSON context blocks with explicit instruction-boundary constraints.

### 2. Provider Routing Matrix
| Mode | Local Ollama Available | Cloud Consent Permitted | Behavior |
|---|---|---|---|
| `AUTO` | Yes | No | Uses Local Ollama |
| `AUTO` | Yes | Yes | Prefers Local Ollama (falls back to Claude on local failure) |
| `AUTO` | No | Yes | Uses Cloud Claude |
| `AUTO` | No | No | AI gracefully unavailable (deterministic pipeline continues) |
| `LOCAL_ONLY` | Yes | Any | Uses Local Ollama |
| `LOCAL_ONLY` | No | Any | AI gracefully unavailable (no cloud call) |
| `CLOUD_ONLY` | Any | Yes | Uses Cloud Claude |
| `CLOUD_ONLY` | Any | No | AI unavailable (consent missing) |
| `DISABLED` | Any | Any | AI completely bypassed |

### 3. Setting Up Local AI (Ollama)
1. Download and install Ollama from [ollama.ai](https://ollama.ai).
2. Start the Ollama daemon:
   ```bash
   ollama serve
   ```
3. Pull a compatible model:
   ```bash
   ollama pull llama3:latest
   # or
   ollama pull qwen3:4b-instruct
   # or
   ollama pull mistral:7b
   ```
4. AEGIS automatically discovers reachable endpoints on `http://127.0.0.1:11434` and selects the best compatible model installed. You can also pin a specific model in `.env` via `OLLAMA_MODEL=llama3:latest`.

### 4. Setting Up Cloud AI (Anthropic Claude)
1. Obtain an API key from [console.anthropic.com](https://console.anthropic.com).
2. Configure `.env`:
   ```env
   ANTHROPIC_API_KEY=sk-ant-api03-...
   ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
   AEGIS_CLOUD_AI_ENABLED=true
   ```
3. Pass `"allow_cloud_ai": true` in analysis requests when users consent to cloud processing.

---

---

## Phase 4: Intelligent Risk Scoring & Deterministic Decision Engine

AEGIS implements a multi-tier, explainable, and deterministic risk scoring engine (`app/services/risk_engine.py`) operating under strict threat supremacy and missing-evidence safety policies.

### 1. Scoring Architecture & Normalized Bands (0–100)
Risk scores are strictly normalized from `0` to `100` and partitioned into 5 standardized risk severity bands:

| Risk Score Band | Risk Severity | Default Action | Interpretation |
|---|---|---|---|
| **0 – 19** | `LOW` | `ALLOW` | Minimal or no observed risk signals across verified completed providers |
| **20 – 39** | `LIMITED` | `WARN` | Low-level anomalies detected (e.g. single engine flag or young domain) |
| **40 – 59** | `MODERATE` | `WARN` | Notable risk indicators (e.g. elevated ML probability or suspicious VT signals) |
| **60 – 79** | `HIGH` | `WARN` / `BLOCK` | Strong corroborating evidence of phishing or credential harvesting |
| **80 – 100** | `CRITICAL` | `BLOCK` | Confirmed malicious threat intelligence or overwhelming malicious consensus |

### 2. Threat Override Policy (Tier 1 Supremacy)
External threat intelligence providers possess authoritative supremacy. A confirmed malicious finding from Google Safe Browsing or VirusTotal consensus immediately triggers high-priority threat overrides:
- **Google Safe Browsing Match**: Threat detected (malware, social engineering, unwanted software) -> **Score: 100**, **Verdict: CRITICAL**, **Action: BLOCK**.
- **VirusTotal Consensus**:
  - `malicious >= 10`: **Score: 100**, **Verdict: CRITICAL**, **Action: BLOCK**.
  - `5 <= malicious <= 9`: **Score: 95**, **Verdict: CRITICAL**, **Action: BLOCK**.
  - `2 <= malicious <= 4`: **Score: 90**, **Verdict: CRITICAL**, **Action: BLOCK**.
- **Both GSB & VirusTotal Consensus Triggered**: **Score: 100**, **Verdict: CRITICAL**, **Action: BLOCK**.
- **Inviolability**: ML legitimate predictions, AI recommendations, old domain age, or registrar reputation **can never downgrade or cancel a confirmed threat**.

### 3. Multi-Source Accumulation (Tier 2 Non-Overridden Scoring)
When no Tier 1 threat override is triggered, the engine calculates a composite risk score based on multi-source evidence:
- **PhishOFE ML Classifier**: Up to 50 points based on calibrated probability:
  - If $P < 0.50$ (or legitimate): **0 points**. Low phishing probability contributes no risk.
  - If $P \ge 0.50$: **`30 + round((P - 0.50) * 40)`** points (smoothly scales from 30 at $P=0.50$ to 50 at $P=1.00$). ML alone never triggers `CRITICAL` (cap 50 < 70).
- **VirusTotal Isolated Detections**: 25 points for an isolated malicious detection; up to 15 points scaled by suspicious engine counts.
- **RDAP Domain Age**:
  - Domain age < 14 days: +15 points.
  - Domain age < 30 days: +10 points.
  - Domain age < 90 days: +5 points.
  - Domain age >= 90 days: 0 points.
  - Unsupported TLDs, missing registration dates, timeouts, and network errors contribute 0 points.
- **DomainShield**: Scheduled for Phase 5 implementation (contributes 0 points in Phase 4).

### 4. Separation of Risk and Confidence (Tier 3 Completeness)
Risk severity is strictly decoupled from evidence completeness. A low observed score with missing providers must never produce a false sense of security:
- **`evidence_completeness`**: Normalized float between `0.0` and `1.0` tracking the proportion of active, completed providers (ML, GSB, VirusTotal, RDAP).
- **`confidence_level`**: Categorical certainty rating:
  - `HIGH`: Completeness >= 0.75 and no major provider contradictions.
  - `MEDIUM`: Completeness >= 0.50.
  - `LOW`: Completeness < 0.50.
- **Safety Qualification Criteria for `SAFE`**:
  To receive a `SAFE` verdict with `ALLOW` action, **all** of the following must hold:
  1. No Tier 1 threat overrides.
  2. Composite risk score < 20.
  3. Evidence completeness >= 0.75 (at least 3 core providers completed).
  4. Google Safe Browsing completed with zero threats.
  5. VirusTotal completed with 0 malicious and 0 suspicious detections.
  6. ML classifier completed and predicted `legitimate`.
  If these criteria are not met, the verdict defaults safely to **`INSUFFICIENT_EVIDENCE`** with action **`WARN`**.

### 5. Deterministic Decision Details
Every analysis response includes structured explainability fields under `decision_details`:
- `supporting_factors`: Direct factual evidence driving risk elevation.
- `benign_factors`: Confirmed legitimate evidence (e.g. established domain age, zero detections).
- `contradictory_factors`: Conflicts between independent sources (e.g. ML predicting phishing on an established bare domain, or AI advising ALLOW against threat signals).
- `missing_factors`: Explicit listing of offline, unconfigured, or timed-out providers.
- `policy_version`: Active scoring policy (`"4.0.0"`).

---

## Running the Server

Start the FastAPI application with auto-reload:
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Root Info**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Health Check**: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)
- **AI Engine Status**: [http://127.0.0.1:8000/api/v1/ai/status](http://127.0.0.1:8000/api/v1/ai/status)
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Root service status and documentation link |
| `GET` | `/api/v1/health` | Service health status and active environment |
| `GET` | `/api/v1/ai/status` | Real-time status of Local Ollama and Cloud AI providers |
| `POST` | `/api/v1/analyze` | Multi-source URL threat analysis (ML, Google, VirusTotal, RDAP, AI) |
| `POST` | `/api/v1/analyze/batch` | Batch URL analysis (1–20 URLs) with optional cloud consent |
| `GET` | `/api/v1/history` | Paginated scan history from SQLite |
| `GET` | `/api/v1/history/{scan_id}` | Detailed scan record, AI explanation, and provider telemetry |
| `POST` | `/api/v1/decisions` | Persist user decision (`PROCEED` or `CANCEL`) |

### Example Request (`POST /api/v1/analyze`)
```json
{
  "url": "https://secure-login.paypal-verification.com/account",
  "source": "chrome_extension",
  "allow_cloud_ai": false
}
```

### Example Response with Decision Engine Telemetry
```json
{
  "scan_id": "324a8a1f-8066-4ed7-870b-4398db30803d",
  "status": "completed",
  "verdict": "SUSPICIOUS",
  "risk_score": 65,
  "action": "WARN",
  "reason": "Elevated risk score (65/100) from corroborating phishing indicators.",
  "confidence_level": "HIGH",
  "evidence_completeness": 1.0,
  "decision_details": {
    "policy_version": "4.0.0",
    "verdict": "SUSPICIOUS",
    "risk_score": 65,
    "action": "WARN",
    "reason": "Elevated risk score (65/100) from corroborating phishing indicators.",
    "confidence_level": "HIGH",
    "evidence_completeness": 1.0,
    "supporting_factors": [
      "ML classifier indicates phishing (probability: 0.9986, +50 pts)",
      "Domain was registered recently (14 days old, less than 30 days, +10 pts)"
    ],
    "benign_factors": [
      "Google Safe Browsing found no malicious threat."
    ],
    "contradictory_factors": [],
    "missing_factors": []
  },
  "checks": {
    "ml": {
      "status": "completed",
      "details": {
        "status": "completed",
        "prediction": "phishing",
        "confidence": 0.9986,
        "phishing_probability": 0.9986,
        "model_name": "PhishOFE-URL-Classifier",
        "model_version": "1.0"
      }
    },
    "google_safe_browsing": {
      "status": "completed",
      "details": {
        "status": "completed",
        "threat_detected": false
      }
    },
    "virustotal": {
      "status": "completed",
      "details": {
        "status": "completed",
        "malicious": 0,
        "suspicious": 0
      }
    },
    "rdap": {
      "status": "completed",
      "details": {
        "status": "completed",
        "domain": "paypal-verification.com",
        "registered": true,
        "domain_age_days": 14,
        "creation_date": "2026-10-16T04:00:00Z"
      }
    },
    "ai": {
      "status": "completed",
      "details": {
        "provider": "local_ollama",
        "model": "qwen3:4b-instruct",
        "status": "success",
        "latency_ms": 1450.2,
        "cloud_used": false,
        "analysis": {
          "short_explanation": "Domain exhibits brand spoofing targeting PayPal with suspicious subdomains and recently created registrar records.",
          "key_suspicious_indicators": [
            "Brand name impersonation in domain name",
            "Domain created within the last 14 days",
            "Random forest classifier assigned 99.8% phishing probability"
          ],
          "benign_indicators": [
            "Valid DNS delegation"
          ],
          "evidence_interpretation": "Indicators strongly support deceptive credential harvesting.",
          "confidence": 0.96,
          "recommended_action": "Do not enter credentials or proceed to this destination."
        }
      }
    },
    "domain_shield": {
      "status": "not_run",
      "details": {}
    }
  },
  "ai_explanation": {
    "provider": "local_ollama",
    "model": "qwen3:4b-instruct",
    "status": "success",
    "latency_ms": 1450.2,
    "cloud_used": false,
    "analysis": {
      "short_explanation": "Domain exhibits brand spoofing targeting PayPal with suspicious subdomains and recently created registrar records.",
      "key_suspicious_indicators": [
        "Brand name impersonation in domain name",
        "Domain created within the last 14 days",
        "Random forest classifier assigned 99.8% phishing probability"
      ],
      "benign_indicators": [
        "Valid DNS delegation"
      ],
      "evidence_interpretation": "Indicators strongly support deceptive credential harvesting.",
      "confidence": 0.96,
      "recommended_action": "Do not enter credentials or proceed to this destination."
    }
  },
  "domain_impersonation": {}
}
```

---

---

## Phase 5: DomainShield & SearchGuard

### DomainShield — Typosquatting & Brand Impersonation Defense
DomainShield detects brand impersonation attacks against major high-value targets (Google, Microsoft, Apple, Amazon, PayPal, Meta, Netflix, GitHub, OpenAI, Chase, Bank of America, Wells Fargo) using a multi-technique pipeline:
1. **URL & Hostname Parsing**: Strict syntactic decomposition.
2. **IDNA & Unicode Homoglyph Normalization**: Punycode decoding (`xn--...`), Unicode NFKC decomposition, and Cyrillic/Greek/Armenian lookalike substitution.
3. **Public Suffix List Extraction**: Precise boundary isolation of subdomain, domain label, and multi-label public suffixes via `tldextract`.
4. **Authoritative Official Brand Whitelist**: Fast-path verification of verified official domains (guaranteeing zero false positives for genuine brand properties).
5. **Damerau-Levenshtein Typosquatting**: Detection of character substitution (`g00gle.com`), insertion (`gooogle.com`), deletion (`gogle.com`), and transposition (`googel.com`).
6. **Subdomain Mimicry**: Identification of brands injected into subdomains of unrelated attacker-controlled domains (e.g., `google.com.attacker.com`).
7. **Brand + Security Keyword Composition**: Detection of brand names combined with deceptive authentication/security keywords (e.g., `paypal-account-update.com`).
8. **False Positive Suppression**: Common English dictionary words (`pineapple`, `chase-the-dream`, `goggles`, `metabolism`) are guarded against false flags.

### SearchGuard — Google Search Results Browser Extension (Manifest V3)
SearchGuard protects users from phishing and malicious search results directly inside Google Search Results Pages (`google.com/search`):
- **Least-Privilege Security**: Manifest V3 extension restricted exclusively to Google search domains and local backend endpoints (no `<all_urls>` or invasive permissions).
- **Destination Extraction & Redirect Unwrapping**: Decodes Google's `/url?q=...` tracking wrappers and extracts the true target destinations.
- **Deduplication & Controlled Batching**: Batches extracted URLs in chunks of up to 20 into `POST /api/v1/analyze/batch`.
- **In-Memory Caching & Throttling**: Background service worker maintains a bounded 10-minute scan cache (max 500 entries) and debounced MutationObservers (350ms) to prevent infinite loops.
- **Secure DOM Rendering**: Injects accessible, color-coded status badges (`SAFE`, `SUSPICIOUS`, `CRITICAL`, `INSUFFICIENT_EVIDENCE`) using safe DOM APIs (strict prohibition of `innerHTML` with untrusted data).
- **Navigation Interception**: Warns and intercepts navigation on dangerous/phishing results, providing security evidence and an explicit choice to return to safety.

### Installing and Running the SearchGuard Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory inside the backend folder (`D:\AEGIS - AI Powered Phishing Detection System\backend\extension`).
5. Ensure the AEGIS backend is running on `http://127.0.0.1:8000`.
6. Visit Google and search for any term (e.g., "paypal login" or "cloud computing"). The SearchGuard badges will appear alongside eligible organic and sponsored results!

---

## Phase 6: Complete System Integration & Hackathon Launch Readiness

AEGIS Phase 6 brings the complete full-stack experience together into a demonstrable, resilient MVP:
- **FastAPI Asynchronous Backend**: High-performance REST service providing single & batch URL analysis, scan history, user decision overrides, and AI status.
- **React + Vite + TypeScript Dashboard**: Modern dark cyber-defense telemetry console with real-time URL scanning, Cloud AI consent toggle, preset attack fixtures, multi-provider evidence inspection (6 tabs), search/filter scan history, and decision override audit controls.
- **Chrome MV3 Browser Extension with SearchGuard**: Real-time protection with `activeTab` URL scanning and inline Google search results protection, working completely independently of whether the dashboard is open.
- **End-to-End Test Suite**: 198 automated unit, integration, and E2E tests validating API contracts, SSRF protections, database persistence, threat supremacy, and brand impersonation defense.
- **Hackathon Demonstration Playbook**: See [docs/DEMO_GUIDE.md](file:///d:/AEGIS%20-%20AI%20Powered%20Phishing%20Detection%20System/backend/docs/DEMO_GUIDE.md) for 9 controlled demonstration scenarios.

### Starting the React Dashboard
```powershell
cd dashboard
npm install
npm run dev
```
Access the dashboard at `http://127.0.0.1:5173`.

---

## Running Automated Tests

Run the full automated test suite (198 unit, integration, router, security, and E2E tests):
```powershell
.\.venv\Scripts\python -m pytest tests/ -v
```

Test coverage includes:
- **Phase 1 & 2 Regressions (42 tests)**: API contracts, database isolation, feature extraction, ML inference, SSRF protection, deterministic risk engine boundaries.
- **Phase 3 Hybrid AI (31 tests)**: Ollama runtime detection, connection refusal handling, model discovery, Ollama local inference, Claude cloud client, consent validation, all 8 routing modes, prompt injection defense, and threat supremacy against AI overrides.
- **Phase 4 Risk Scoring Engine (25 tests)**: Score boundaries, deterministic repeatability, threat overrides (GSB & VT), calibrated ML probability scaling, bare-domain contradiction mitigation, RDAP domain age tiers, unsupported TLD handling, evidence completeness & confidence classification.
- **Phase 5 DomainShield Unit Tests (73 tests)**: Official domain clean verification, character substitution, insertion, deletion, transposition, homoglyph attacks, zero-width space/bidi override attacks, Punycode domains, subdomain impersonation, brand+keyword composition, false-positive exclusions.
- **Phase 5 DomainShield Integration Tests (9 tests)**: Analyzer concurrent execution, provider failure isolation, risk engine scoring, failed/unavailable DomainShield SAFE disqualification, API and batch contracts.
- **Phase 5 SearchGuard Extension Tests (9 tests)**: Manifest V3 security validation, least-privilege permissions, extension files integrity, Google redirect unwrapping, destination filtering, and batch endpoint size constraints.
- **Phase 6 End-to-End Integration Tests (9 tests)**: Complete API pipeline, scan history and detail retrieval, user override decisions, SearchGuard batch compatibility, batch limit enforcement, DomainShield brand impersonation, official brand verification, SSRF/scheme validation, and 404 error handling.

---

## Known Limitations

- **URL-Only ML**: The ML model analyzes lexical and structural URL patterns without executing JavaScript or rendering DOM content.
- **Bare-Domain Training Bias**: Known bias where high-reputation bare domains with deep paths may yield high ML phishing probabilities; the risk engine detects this contradiction and mitigates it when threat intelligence is clean.
- **External API Keys**: Google Safe Browsing and VirusTotal require external API keys. If keys are missing, the system gracefully marks their status as `unavailable` and falls back to `INSUFFICIENT_EVIDENCE` or ML/RDAP risk scoring.
- **Live Local LLM Latency**: First inference on cold-started local models may experience an initial model weight loading latency of 10–15 seconds before caching in RAM.
- **Browser GUI Automation Environment**: Automated tests validate extension manifest, JavaScript logic, URL unwrapping, and API contracts. Real-browser interactive testing in headless sandbox is constrained; manual unpacked extension verification is documented in the Demo Guide.

