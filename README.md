# AEGIS — AI-Powered Phishing & Malicious URL Protection System

AEGIS is an enterprise-grade cybersecurity protection platform designed to identify, analyze, and neutralize phishing, homoglyph, and deceptive URLs in real time.

---

## Workspace Structure & Ownership Boundary

```text
AEGIS/
├── frontend/                     # React + Vite + TypeScript Web Application
│   ├── src/
│   │   ├── components/           # Logo, Preloader, Scanner, VerdictCard, ThreatReport, Layout
│   │   ├── pages/                # Home, ScanResult, History, HistoryDetail, Settings, NotFound
│   │   ├── services/             # API client, HTTP error handling, health diagnostics
│   │   ├── types/                # Shared TypeScript contracts and API schemas
│   │   └── styles/               # Tailwind CSS & design tokens
│   ├── index.html
│   └── package.json
├── extension/                    # Chrome Manifest V3 Browser Extension
│   ├── src/
│   │   ├── background/           # Service Worker with one-time approval loop prevention
│   │   ├── content/              # Navigation Guard (link interception) & SearchGuard (Google badges)
│   │   ├── popup/                # Extension toolbar popup (React + Tailwind)
│   │   ├── interstitial/         # Security warning interstitial (React + Tailwind)
│   │   └── services/             # Extension API client
│   ├── dist/                     # Unpacked extension output (ready to load in Chrome)
│   ├── manifest.json             # Manifest V3 specification
│   └── package.json
└── backend/                      # Backend Service (Owned by Backend Team)
    └── README.md                 # Reserved exclusively for the backend developer
```

---

## Core Security & Architecture Principles

1. **Deterministic Security Policy**: Multi-engine detection (Machine Learning classifier, Google Safe Browsing, VirusTotal, RDAP domain intelligence, DomainShield lookalike analysis) synthesized by backend policy engine into `SAFE`, `SUSPICIOUS`, or `CRITICAL`.
2. **Strict No-Mock-Data Mandate**: Zero fabricated scan data, mock statistics, or simulated success states. If the backend is unreachable, the system renders an honest, transparent diagnostic state.
3. **One-Time Approval Loop Prevention**: Resumed navigation of safe links consumes a narrow, 15-second single-use token to avoid infinite interception loops without creating insecure global domain allowlists.
4. **Permanent Critical Blocking**: Critical malicious links cannot be bypassed by the user. Direct proceed buttons are permanently disabled.
5. **Zero Client Secrets**: Third-party threat intelligence credentials (Google Safe Browsing, VirusTotal, Claude API) are kept exclusively server-side.

---

## Quick Start

### 1. Run Frontend Web App
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

### 2. Build & Load Chrome Extension
```bash
cd extension
npm install
npm run build
# In Chrome: chrome://extensions -> Developer mode -> Load unpacked -> select AEGIS/extension/dist
```

### 3. Backend Integration
The frontend and extension connect to `http://localhost:8000` by default. This URL can be changed dynamically in the **Settings** page or extension popup.
