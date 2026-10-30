# AEGIS — Frontend Web Application

The frontend user interface for **AEGIS (AI-Powered Phishing & Malicious URL Protection System)**.

Built with **React**, **TypeScript**, **Vite**, **Tailwind CSS**, **Framer Motion**, and **React Router**.

---

## Architecture & Design System

Following the primary PRD (`AEGIS_Frontend_Extension_UI_PRD.md`) and **UI UX Pro Max** design guidelines:

- **Aesthetic**: Premium, minimalist modern cybersecurity interface.
- **Palette**: Deep Navy (`#071B3A`, `#0B2447`), restrained royal blue accents (`#1D4ED8`, `#2563EB`), crisp white cards with subtle slate borders (`#E2E8F0`), and Slate 50 background (`#F8FAFC`).
- **Typography**: Clean system sans-serif hierarchy with monospaced data accents.
- **Preloader**: Mac-inspired minimalist startup screen (pure white background, centered dark navy AEGIS shield logo, wordmark, slim loading indicator, smooth entrance). Respects `prefers-reduced-motion`.
- **Verdict Cards**: High-contrast, multi-signal indicators (color + bold label + icon + screen-reader announcement):
  - **SAFE**: Emerald check, reassuring text ("No active threat indicators detected").
  - **SUSPICIOUS**: Amber warning with rationale and evidence breakdown.
  - **CRITICAL**: Malicious alert banner, blocked state with **no proceed/bypass button**.
  - **UNABLE TO VERIFY**: Honest fail-safe notice for incomplete checks or provider timeouts.
- **Zero Mock Data**: In strict accordance with security requirements, the app queries real REST endpoints under `/api/v1`. If the backend is offline or an endpoint is pending implementation, an honest connection notice is rendered.

---

## Routes & Views

| Route | View | Description |
|---|---|---|
| `/` | `Home` | Minimalist URL scanner with validation, live progress, and verdicts |
| `/scan/:scanId` | `ScanResultPage` | Full threat report and verdict inspection for a scan ID |
| `/history` | `HistoryPage` | Real scan records from `GET /api/v1/history` with verdict filtering |
| `/history/:scanId` | `HistoryDetailPage` | Detailed historical report from `GET /api/v1/history/{scan_id}` |
| `/settings` | `SettingsPage` | Configurable API base URL, live `GET /api/v1/health` diagnostic, coverage & privacy info |

---

## Backend API Contract

The frontend connects to the following endpoints (defaulting to `http://localhost:8000`):

- `POST /api/v1/analyze`: Analyse URL with `{ url, source: "dashboard" }`
- `GET /api/v1/status/{scan_id}`: Poll scan status
- `GET /api/v1/verdict/{scan_id}`: Retrieve final verdict
- `GET /api/v1/history`: Retrieve authorized scan history
- `GET /api/v1/history/{scan_id}`: Retrieve scan details
- `GET /api/v1/health`: Live health status diagnostic

---

## Development & Build

```bash
# Install dependencies
npm install

# Start local development server (http://localhost:3000)
npm run dev

# Run TypeScript type check and production bundle build
npm run build
```
