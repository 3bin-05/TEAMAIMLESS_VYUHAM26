# AEGIS — AI-Powered Phishing & Malicious URL Protection System

<p align="center">
  <strong>Multi-layered, real-time threat detection combining Machine Learning, Cyber Threat Intelligence, Network Heuristics, and Local AI Reasoning.</strong>
</p>

---

## 📌 Project Overview

**AEGIS** is an intelligent cybersecurity defense system designed to protect users against phishing attacks, malicious links, and deceptive redirects before harm occurs. It provides end-to-end protection across:

1. **FastAPI Backend (`backend/`)**: High-performance detection engine fusing pre-trained ML classifiers (`XGBoost`), cybersecurity heuristics (DNS, TLS/SSL, HTTP headers, redirects), external threat intelligence (VirusTotal, Google Safe Browsing), and optional local AI reasoning (via Ollama).
2. **Modern Web Dashboard (`frontend/`)**: Modern web UI built with React 19, Vite, TypeScript, and Tailwind CSS v4 for manual URL scanning, threat intelligence inspection, and audit history.
3. **Chrome Extension (`extension/`)**: Manifest V3 browser extension featuring **Navigation Guard** (intercepts malicious link clicks before navigation) and **Google SearchGuard** (live risk badges on Google search results).

---

## 🏗️ Architecture & Detection Pipeline

```
[ User Action: Web App / Extension / SearchGuard ]
                      │
                      ▼
             FastAPI REST Backend
         (POST /api/v1/analyze)
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
   ┌───────────┐ ┌───────────┐ ┌────────────────┐
   │ ML Engine │ │   Cyber   │ │  Threat Intel  │
   │ (XGBoost) │ │ Heuristics│ │  (VirusTotal,  │
   │ Feature   │ │ DNS, TLS, │ │ Google Safe    │
   │ Extraction│ │ Headers   │ │   Browsing)    │
   └─────┬─────┘ └─────┬─────┘ └───────┬────────┘
         │             │               │
         └─────────────┼───────────────┘
                       ▼
            ┌─────────────────────┐
            │    Aegis Engine     │
            │ Risk Score [0–100]  │
            │  SAFE / SUSPICIOUS  │
            │     / CRITICAL      │
            └──────────┬──────────┘
                       │ (Optional Context Enrichment)
                       ▼
            ┌─────────────────────┐
            │  Local AI (Ollama)  │
            │ Human-readable      │
            │ explanation/findings│
            └─────────────────────┘
```

---

## 📁 Repository Folder Structure

```
Aegis/
├── README.md                      # Primary project documentation
│
├── backend/                       # Python FastAPI Backend Service
│   ├── .env                       # Local environment variables (active)
│   ├── .env.example               # Template environment configuration
│   ├── requirements.txt           # Python dependencies (FastAPI, XGBoost, Uvicorn, etc.)
│   ├── main.py                    # Server entrypoint (runs uvicorn on port 8000)
│   ├── aegis_engine/              # Core threat scoring & evaluation pipeline
│   │   ├── engine.py              # AegisEngine class orchestrating multi-layer analysis
│   │   ├── scoring.py             # Risk score calculation and verdict boundaries
│   │   └── exceptions.py          # Custom engine exceptions
│   ├── api/                       # API application layer
│   │   ├── app.py                 # FastAPI application factory and error handlers
│   │   ├── middleware.py          # CORS, Security Headers, and Request ID middlewares
│   │   ├── dependencies.py        # Dependency injection for engine and models
│   │   ├── errors.py              # Centralized JSON error formatters
│   │   ├── routes/                # Endpoint routers
│   │   │   ├── health.py          # GET /health, GET /api/v1/ready
│   │   │   └── analysis.py        # POST /api/v1/analyze, POST /api/v1/analyze-batch
│   │   └── schemas/               # Pydantic v2 validation models
│   │       ├── analysis.py        # AnalyzeRequest, AnalyzeResponse, etc.
│   │       └── health.py          # HealthResponse, ReadinessResponse
│   ├── cyber_analysis/            # Network & infrastructure analysis
│   │   ├── dns_analyzer.py        # DNS lookup, MX/TXT records, fast-flux detection
│   │   ├── tls_analyzer.py        # SSL/TLS certificate validation and expiration
│   │   ├── http_analyzer.py       # HTTP status, security headers (HSTS, CSP)
│   │   └── redirect_analyzer.py   # Hop-by-hop redirect chain auditing
│   ├── cybersec_tools/            # Threat intelligence integrations
│   │   ├── virustotal.py          # VirusTotal v3 API client
│   │   ├── safe_browsing.py       # Google Safe Browsing v4 lookup
│   │   └── phishtank.py           # PhishTank integration
│   ├── ml_model/                  # Machine Learning classifier
│   │   ├── model.py               # Pre-trained model loading and prediction
│   │   ├── feature_extraction.py  # 30+ lexical, structural, and domain features
│   │   └── weights/               # Saved model artifacts (.pkl, .joblib, or .bin)
│   ├── local_ai/                  # Local LLM explanation layer
│   │   ├── provider.py            # Ollama API client connector
│   │   ├── analyzer.py            # AI prompt builder and finding summarizer
│   │   └── models.py              # AI response schemas and status enums
│   ├── firebase/                  # Cloud persistence (optional)
│   │   └── firestore.py           # Scan history and audit logging
│   ├── cache/                     # Low-latency TTL in-memory cache
│   └── tests/                     # Unit, integration, and security test suites
│
├── frontend/                      # React 19 + Vite Dashboard
│   ├── package.json               # Frontend dependencies & npm scripts
│   ├── vite.config.ts             # Vite configuration (port 3000)
│   ├── index.html                 # Single Page Application HTML root
│   ├── public/                    # Static assets & icons
│   └── src/
│       ├── main.tsx               # React application root entrypoint
│       ├── App.tsx                # Client-side router configuration
│       ├── index.css              # Global styles & Tailwind CSS v4 directives
│       ├── components/            # Reusable UI components
│       │   ├── layout/            # Navbar, Header, Footer
│       │   ├── home/              # URL Input box, live scanner, verdict cards
│       │   └── ui/                # Buttons, modals, badges, preloader
│       ├── pages/                 # Route views
│       │   ├── Home.tsx           # Primary scanner & verdict screen
│       │   ├── ScanResultPage.tsx # Detailed scan result report by ID
│       │   ├── HistoryPage.tsx    # Searchable scan history
│       │   ├── HistoryDetailPage.tsx # Deep-dive into historical signals
│       │   ├── SettingsPage.tsx   # Configurable API base URL & health diagnostic
│       │   └── CoveragePrivacyPage.tsx # Threat coverage & privacy disclosures
│       ├── services/
│       │   └── api-client.ts      # Typed REST client communicating with backend
│       └── types/                 # TypeScript interfaces and API schemas
│
└── extension/                     # Chrome Browser Extension (Manifest V3)
    ├── manifest.json              # Extension manifest (MV3, permissions, content scripts)
    ├── package.json               # Extension dependencies & build scripts
    ├── vite.config.ts             # Extension Vite multi-entry build config
    ├── popup.html                 # Extension toolbar popup entrypoint
    ├── interstitial.html          # Fullscreen warning interstitial for blocked links
    └── src/
        ├── background/            # Background service worker
        │   ├── index.ts           # Service worker entrypoint
        │   └── navigation-state.ts# Single-use loop-prevention token store
        ├── content/               # Content scripts injected into web pages
        │   ├── navigation-guard.ts# Intercepts outgoing link clicks before navigation
        │   └── search-guard.ts    # Badges Google Search organic results in real-time
        └── popup/                 # React popup UI (threat stats, toggle protection)
```

---

## ⚡ Prerequisites

Before running locally, make sure you have installed:

| Tool | Recommended Version | Purpose |
|---|---|---|
| **Python** | 3.10 – 3.14 | Backend API & ML inference |
| **Node.js** | v20+ (v26 verified) | Frontend & Extension development |
| **npm** | v10+ | Package manager |
| **Google Chrome** | Latest | To load the browser extension |
| **Ollama** *(Optional)* | Latest | For local AI explanations (`qwen3:4b-instruct`) |

---

## 🚀 How to Run Locally

### 1. Run the Backend (FastAPI)

#### Step 1: Open a terminal in `backend/`
```bash
cd backend
```

#### Step 2: Create and activate a Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```
- **macOS / Linux**:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

#### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: Configure Environment Variables
Copy `.env.example` to `.env` if not already present:
```bash
cp .env.example .env
```
*(Key configurations in `.env` include `AEGIS_API_PORT=8000`, `AEGIS_CORS_ORIGINS`, and optional API keys for VirusTotal and Google Safe Browsing).*

#### Step 5: Start the Backend Server
```powershell
# Windows
.\.venv\Scripts\python.exe main.py

# Or via uvicorn directly:
.\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000 --reload
```
```bash
# macOS / Linux
python main.py
```

The API will now be live:
- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Health Check**: `http://127.0.0.1:8000/api/v1/health`

---

### 2. Run the Frontend (React + Vite)

#### Step 1: Open a second terminal in `frontend/`
```bash
cd frontend
```

#### Step 2: Install Node Dependencies
```bash
npm install
```

#### Step 3: Start the Vite Development Server
```bash
npm run dev
```

The web dashboard will be available at:
- **Web App URL**: `http://localhost:3000`

The dashboard automatically connects to `http://localhost:8000`. You can test by typing any URL (e.g. `https://google.com` or `http://suspicious-phish-domain.xyz`) and clicking **Scan**.

---

### 3. Build & Load the Chrome Extension (Optional)

#### Step 1: Build the Extension
In a third terminal inside `extension/`:
```bash
cd extension
npm install
npm run build
```
This compiles the extension bundle into `extension/dist/`.

#### Step 2: Load into Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** via the toggle switch in the top-right corner.
3. Click the **Load unpacked** button.
4. Browse to and select the `Aegis/extension/dist` folder.
5. The **AEGIS** shield icon will appear in your Chrome toolbar.
6. Links you click will now be protected by Navigation Guard, and Google searches will feature SearchGuard badges!

---

## 📡 Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Lightweight service health status |
| `GET` | `/api/v1/ready` | Readiness check for ML and cyber analysis modules |
| `POST` | `/api/v1/analyze` | Primary URL analysis (`{ "url": "https://example.com" }`) |
| `POST` | `/api/v1/analyze-batch` | Batch URL analysis for multiple links concurrently |
| `GET` | `/docs` | Interactive Swagger API documentation |
| `GET` | `/redoc` | ReDoc API specification |

---

## 🧪 Testing

To run the backend test suite:
```powershell
cd backend
.\.venv\Scripts\pytest
```

To run frontend type-checking and linting:
```bash
cd frontend
npm run build
npm run lint
```

---

## 🔒 Security & Privacy

- **Zero Secret Exposure**: Third-party API keys (VirusTotal, Google Safe Browsing) are strictly stored and queried on the backend.
- **Fail-Safe Design**: If any analysis tier experiences timeouts, the engine defaults to `UNABLE TO VERIFY` or flags suspicious uncertainty rather than falsely marking unknown links as safe.
- **Loop Prevention**: Intercepted links that are validated as safe receive a single-use token valid for 15 seconds to prevent browser redirect loops.
