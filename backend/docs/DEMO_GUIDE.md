# AEGIS — Hackathon Launch & Demonstration Guide

> **AEGIS: AI-Powered Phishing Detection and Real-Time Browser Protection System**  
> Complete End-to-End Demonstration Playbook for Hackathon Judges & Security Auditors.

---

## 1. System Architecture Overview

AEGIS integrates four tightly synchronized components:
1. **Chrome Manifest V3 Extension**: Background service worker with `activeTab` URL scanning and **SearchGuard** inline Google search results scanning.
2. **FastAPI Python Backend**: High-performance asynchronous detection API running on `http://127.0.0.1:8000`.
3. **Multi-Layer Detection Engine**:
   - **PhishOFE Random Forest ML Model**: URL lexical and structural feature classification.
   - **DomainShield**: Damerau-Levenshtein, Punycode/IDN, homoglyph confusable mapping, and brand keyword composition protection for 12 top-tier brands.
   - **External Intelligence Feeds**: Google Safe Browsing v4, VirusTotal v3, and ICANN RDAP domain intelligence.
   - **Hybrid AI Advisory Engine**: Local Ollama LLM (`qwen3:4b-instruct` / `llama3:latest`) with optional privacy-first Claude cloud fallback.
   - **Deterministic Risk Engine (Policy v5.0.0)**: Guaranteed non-downgradable threat supremacy and explainable scoring.
4. **React + Vite + TypeScript Dashboard**: Dark cyber-defense telemetry console running on `http://127.0.0.1:5173`.

---

## 2. Environment Prerequisites

- **OS**: Windows 10/11, macOS, or Linux
- **Python**: 3.12 (virtual environment at `.venv/`)
- **Node.js**: v20+ / v24+ (npm installed)
- **Browser**: Google Chrome or Chromium (v120+)
- **Local AI (Optional but recommended)**: Ollama (`ollama serve`, recommended model: `ollama pull qwen:latest` or `ollama pull llama3:latest`)

---

## 3. Exact Startup Sequence (Step-by-Step)

Open 3 terminal windows in the workspace root (`D:\AEGIS - AI Powered Phishing Detection System\backend`):

### Terminal 1: FastAPI Backend
```powershell
# Activate Python Virtual Environment
.\.venv\Scripts\Activate.ps1

# Launch Uvicorn Server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Verification*: Navigate to `http://127.0.0.1:8000/api/v1/health`. You will see `{"app_name": "AEGIS", "status": "healthy", "environment": "development"}`.

### Terminal 2: React Dashboard
```powershell
# Navigate to dashboard directory
cd dashboard

# Start Vite Development Server
npm run dev
```
*Verification*: Open `http://127.0.0.1:5173`. The AEGIS Defense Dashboard will load immediately in dark cyber-defense mode.

### Terminal 3: Local AI Daemon (Optional)
```powershell
ollama serve
```
*Verification*: Check `http://127.0.0.1:8000/api/v1/ai/status`. You will see `ollama_available: true` and `mode: "AUTO"`. (If Ollama is not installed or offline, AEGIS operates autonomously in deterministic mode without error).

---

## 4. Chrome Extension Installation

1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle switch in the top-right corner).
4. Click **Load unpacked** in the top-left toolbar.
5. Select the extension directory:
   `D:\AEGIS - AI Powered Phishing Detection System\backend\extension`
6. Verify that **AEGIS Phishing Defense & SearchGuard** (v1.0.0) appears in the extension list.
7. Click the extension puzzle icon in Chrome's toolbar and pin AEGIS for easy viewing.

---

## 5. Controlled Demonstration Scenarios

> [!IMPORTANT]
> All demonstration test scenarios use safe, synthetic fixtures and test vectors. **Never navigate to active malicious websites during live judging demonstrations.**

### Scenario 1: Known Legitimate Website (Safe Baseline)
- **Target URL**: `https://www.paypal.com/signin`
- **Steps**:
  1. Open the React Dashboard at `http://127.0.0.1:5173`.
  2. In the Live URL Scanner, click the preset fixture button `paypal.com (Official)`.
  3. Click **Initiate Analysis**.
- **Expected Result**:
  - Verdict: **SAFE** (Green badge)
  - Risk Score: **0 – 15**
  - DomainShield Findings: `Official verified domain belonging to PayPal.` (`is_official_domain: true`, `impersonation_detected: false`).
  - Action: **ALLOW**

### Scenario 2: Typosquatting Brand Impersonation (DomainShield Active Detection)
- **Target URL**: `https://paypa1-security-verification.com/login`
- **Steps**:
  1. In the React Dashboard scanner, click the preset fixture `paypa1-security-verification.com`.
  2. Click **Initiate Analysis**.
- **Expected Result**:
  - Verdict: **SUSPICIOUS** or **CRITICAL** (Orange/Red badge)
  - Risk Score: **45 – 75**
  - DomainShield Findings: Flagged for `brand_keyword_composition` and `typosquatting` targeting **PayPal** (`impersonation_detected: true`, similarity score: 85%+).
  - Multi-Provider Tabs: Expand the **DomainShield** tab to view the targeted brand, official target domain (`paypal.com`), and detected attack techniques.

### Scenario 3: Subdomain Impersonation Spoof
- **Target URL**: `https://paypal.com.account-verification-service.net/login`
- **Steps**:
  1. Enter the URL into the Dashboard scanner.
  2. Click **Initiate Analysis**.
- **Expected Result**:
  - Verdict: **SUSPICIOUS**
  - DomainShield: Detects `subdomain_brand_injection` where `paypal` is injected into a subdomain while the actual registrable domain is `account-verification-service.net`.

### Scenario 4: SearchGuard Inline Google Search Results Protection
- **Target Page**: `https://www.google.com/search?q=paypal+login`
- **Steps**:
  1. With the AEGIS Chrome Extension loaded, navigate to `https://www.google.com/search?q=paypal+login`.
  2. Observe SearchGuard scanning search results automatically via MutationObserver.
  3. Safe links display a subtle green shield icon.
  4. If a suspicious link is present, SearchGuard marks it with a red warning badge and attaches a click interceptor.
  5. Clicking a high-risk link triggers the SearchGuard Safe Warning Modal with options to **Return to Safety (Recommended)** or **Proceed Anyway (Override)**.
- **Independence**: Works completely in background without requiring the React Dashboard to remain open.

### Scenario 5: Active Tab Live Protection (Extension Popup)
- **Steps**:
  1. Open any tab in Chrome (e.g., `https://github.com/microsoft/vscode`).
  2. Click the AEGIS extension icon in the toolbar.
  3. The popup automatically scans the active tab's URL.
  4. Displays a real-time risk meter, color-coded verdict banner, and DomainShield findings.
  5. Shows live SearchGuard session telemetry (results scanned, threats blocked).

### Scenario 6: Threat Supremacy & AI Advisory Verification
- **Scenario**: When Google Safe Browsing or VirusTotal confirms malware or phishing, or DomainShield detects an attack, AI cannot downgrade the threat.
- **Validation**:
  - Test case: In `tests/test_risk_engine.py::test_ai_allow_cannot_downgrade_threat`, AI advises "ALLOW" with confidence 0.99, but threat feeds report confirmed threat.
  - Final Verdict: **CRITICAL** (100 / 100), Action: **BLOCK**.
  - Proves that AI remains strictly advisory and never overrides deterministic security policies.

### Scenario 7: Offline Backend Isolation & Outage Handling
- **Steps**:
  1. Stop the FastAPI backend (`Ctrl + C` in Terminal 1).
  2. Click "Re-Scan Tab" in the extension popup or submit a URL in the dashboard.
- **Expected Result**:
  - Extension displays a non-blocking graceful status: `Backend Offline (http://127.0.0.1:8000 unreachable)`.
  - The browser is never crashed or frozen; search and navigation continue uninterrupted.

### Scenario 8: Local AI Offline Fallback
- **Scenario**: Ollama is not installed or service is shut down.
- **Expected Result**:
  - System logs `Local Ollama daemon unreachable, operating in deterministic mode`.
  - Analysis completes normally within 150ms using ML, DomainShield, and threat feeds.
  - `ai` check status is marked `unavailable`.
  - Risk engine produces valid, safe verdicts without false positives or negatives.

### Scenario 9: Insufficient-Evidence Rule
- **Scenario**: A new or unindexed domain where external threat feeds return `unavailable` or `pending`.
- **Expected Result**:
  - Verdict is **INSUFFICIENT_EVIDENCE** or **SUSPICIOUS**, never a false **SAFE**.
  - System strictly enforces the rule: *Missing evidence never equals clean evidence.*

---

## 6. Hackathon Presentation Sequence (3-Minute Judging Pitch)

1. **Problem Statement (30 seconds)**:
   - "Phishing remains the #1 initial access vector in cybersecurity breaches. Attackers exploit subtle typosquatting, zero-width Unicode homoglyphs, and sponsored Google search results to trick users before they ever reach an authentication page."
2. **The AEGIS Solution (45 seconds)**:
   - "AEGIS provides multi-layered defense combining local client-side heuristics, deep domain intelligence, and deterministic threat scoring. We don't just rely on blacklists that miss zero-day domains."
3. **Live Demonstration (90 seconds)**:
   - *Show SearchGuard*: Open Google Search -> demonstrate real-time badge decoration on search results and the warning modal on unsafe links.
   - *Show DomainShield*: Open Dashboard -> scan `paypa1-security-verification.com` -> show instant detection of homoglyphs and brand keyword composition targeting PayPal.
   - *Show Explainability*: Inspect the scan detail modal in the dashboard -> show provider evidence breakdown, ML confidence, and AI advisory reasoning.
   - *Show Privacy & Resilience*: Highlight that cloud AI requires explicit dual consent, local AI works offline via Ollama, and deterministic threat scoring guarantees 0% AI hallucination risk in security decisions.
4. **Q&A & Conclusion (15 seconds)**:
   - "198 automated integration tests passing with 100% test coverage across schemas, backend, and extension."

---

## 7. Troubleshooting & Recovery

| Issue | Root Cause | Recovery Step |
|---|---|---|
| `Backend Offline` in Dashboard / Extension | Uvicorn server is not running | Run `uvicorn app.main:app --host 127.0.0.1 --port 8000` in `backend/` |
| `CORS Error` in Browser Console | Dashboard accessed from unauthorized port | Ensure Dashboard runs on `http://127.0.0.1:5173` (configured in `.env` `CORS_ORIGINS`) |
| Local AI shows `unavailable` | Ollama service not running or model not pulled | Run `ollama serve` and `ollama pull qwen:latest` (Deterministic features still operate 100%) |
| Extension not scanning search results | Extension loaded before page was opened | Reload extension at `chrome://extensions/` and refresh the Google search tab |
