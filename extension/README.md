# AEGIS — Chrome Extension (Manifest V3)

The browser extension for **AEGIS (AI-Powered Phishing & Malicious URL Protection System)**.

Built with **Chrome Manifest V3**, **TypeScript**, **React**, **Vite**, and **Tailwind CSS**.

---

## Key Features & Security Architecture

### 1. Navigation Guard
- Intercepts eligible HTTP/HTTPS link clicks on supported web pages before network navigation begins.
- Pauses navigation and queries the AEGIS backend (`POST /api/v1/analyze` with `source: "chrome_extension"`).
- Displays an accessible in-page interstitial overlay with real-time analysis status.
- Applies deterministic security decisions:
  - **SAFE**: Resumes navigation cleanly.
  - **SUSPICIOUS**: Displays caution notice with reasons and requires explicit user confirmation ("Proceed at Own Risk" vs "Return to Safety"). Logs user decision to `POST /api/v1/decisions`.
  - **CRITICAL**: Permanently blocks navigation. **No bypass or proceed action is provided.**
  - **INSUFFICIENT EVIDENCE / ERROR**: Displays fail-safe notice, never assuming safety.

### 2. Loop Prevention & One-Time Approval (Section 14.6 P0)
- Prevents infinite interception loops when a safe link is resumed.
- Upon a `SAFE` + `ALLOW` verdict, the service worker generates a short-lived (15s) single-use approval token keyed by `(tabId, normalizedUrl, attemptId)`.
- When the resumed navigation occurs, the content script and background match and **immediately consume** the token.
- Narrowly scoped: does not create permanent domain allowlists; redirects to different destinations require fresh evaluation.

### 3. Google SearchGuard (Section 9 & 15)
- Automatically monitors organic search result containers on Google Search pages (`div.g`, `#rso`, etc.).
- Normalizes and deduplicates URLs, resolving Google redirect wrappers (`/url?q=...`).
- Submits URLs in bounded, debounced batches to `POST /api/v1/analyze/batch` with `source: "search_guard"`.
- Attaches real-time security badges beside search result titles:
  - **Checking**: Blue spinner badge
  - **Safe**: Emerald shield check
  - **Suspicious**: Amber warning
  - **Critical**: Crimson threat block
  - **Unable to Verify**: Slate info badge
- Uses `MutationObserver` to handle dynamic infinite scroll without duplicate requests or breaking Google Search.
- Clicking an annotated search result still undergoes Navigation Guard evaluation.

### 4. Zero Secrets Policy
- Zero third-party provider API keys (Google Safe Browsing, VirusTotal, Claude API) are bundled or stored in the extension. All threat intelligence queries run server-side.

---

## How to Load in Google Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions`.
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked**.
5. Select the `dist/` directory inside `extension/` (i.e. `AEGIS/extension/dist`).
6. The **AEGIS** icon will appear in the Chrome toolbar. Click it to open the popup or configure the backend URL (default `http://localhost:8000`).

---

## Development & Build

```bash
# Install dependencies
npm install

# Build extension bundle into dist/
npm run build

# Watch mode for iterative extension development
npm run dev
```
