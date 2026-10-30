# AEGIS Frontend & Chrome Extension UI/UX Product Requirements Document

**Product:** AEGIS --- AI-Powered Phishing Detection and Browser
Protection System\
**Document type:** Frontend and Browser Extension UI/UX Product
Requirements Document\
**Version:** 1.1\
**Date:** 30 October 2026\
**Status:** Implementation brief for Antigravity\
**Related specifications:** AEGIS_PRD.md v1.0 and AEGIS_SRS.md v1.0

------------------------------------------------------------------------

## 1. Purpose

This document defines the user interface, user experience, frontend
application, and Chrome Extension requirements for AEGIS. It is intended
to be used as the primary implementation brief by Antigravity.

The implementation must deliver a clean, responsive, accessible,
reliable user experience while integrating with a separately developed
AEGIS backend.

**Important ownership boundary:** the backend is being developed by
another team member. Antigravity must create the `backend/` folder but
must not implement, modify, or populate backend application code. The
frontend and extension must be implemented in their respective folders
and prepared to integrate with the agreed backend API.

## 2. Product overview and source alignment

AEGIS protects users from phishing, malicious, deceptive, and
impersonation URLs. The supplied AEGIS PRD and SRS define the system's
core detection and policy behaviour:

-   User-facing verdicts: `SAFE`, `SUSPICIOUS`, and `CRITICAL`.
-   Internal states include `INSUFFICIENT_EVIDENCE`, `PENDING`, and
    `ERROR`.
-   A deterministic backend policy engine determines the final verdict
    and action.
-   The AI explanation is advisory; it does not override mandatory
    security policy.
-   Provider failures and incomplete evidence must never be presented as
    a Safe result.
-   SearchGuard checks eligible organic Google search results and adds
    status badges.
-   DomainShield can identify possible lookalike domains and suggest a
    legitimate domain only when it is present in a trusted mapping.
-   The extension must clearly communicate its supported navigation
    coverage and must not claim universal interception without
    implementation and test evidence.

This UI/UX document expands the supplied specifications only where
needed to define screens, interactions, frontend architecture, and
implementation instructions.

## 3. Strict implementation instructions for Antigravity

1.  Use the **UI UX Pro Max** skill available in Antigravity before
    designing or implementing the interface. Follow its design-system,
    usability, accessibility, and responsive-design guidance.
2.  Build the frontend with **React, TypeScript, Vite, Tailwind CSS, and
    Framer Motion**.
3.  Build the Chrome Extension using **Chrome Manifest V3**, JavaScript
    or TypeScript, and React for extension UI where appropriate.
4.  Create exactly these top-level project folders:
    -   `frontend/`
    -   `extension/`
    -   `backend/`
5.  `backend/` must remain empty apart from an optional `.gitkeep` or a
    short README explaining that the backend is owned by another
    developer. **Do not create backend source code, API routes, database
    code, model code, or provider integrations in this folder.**
6.  Implement the complete frontend in `frontend/` and the complete
    extension in `extension/`.
7.  **STRICT: DO NOT USE MOCK DATA ANYWHERE.** Do not add fake scan
    results, fabricated statistics, sample history entries, fake threat
    reports, placeholder verdicts, simulated provider results, or
    hardcoded demonstration URLs presented as real data. Do not create a
    mock API mode.
8.  If the backend is not running or an endpoint is not yet available,
    show a proper connection, loading, empty, or error state. Do not
    invent a successful response. Real API integration must use the
    agreed backend contract.
9.  Do not expose backend provider API keys or secrets in frontend
    bundles, extension files, or browser storage.
10. Keep the frontend and extension modular, typed, testable, and ready
    for the backend developer to connect.
11. Do not silently change backend contracts. If a required response
    field is not defined, document the question and coordinate with the
    backend developer.
12. Do not claim the product is bug-free merely because it builds.
    Validate it with tests and real browser workflows; fix discovered
    defects before declaring a feature complete.

## 4. Product goals

-   Make URL checking obvious and effortless.
-   Warn users before they visit a suspicious destination in supported
    navigation flows.
-   Block Critical destinations in supported navigation flows without a
    proceed bypass.
-   Explain why a Suspicious or Critical URL received its verdict.
-   Make Google search results easier to assess by showing clear
    security badges.
-   Present technical evidence in a readable hierarchy without
    overwhelming ordinary users.
-   Provide an accessible scan history and detailed report when backend
    history endpoints are available.
-   Keep the homepage minimal and focused on URL scanning.
-   Ensure all visible scan information comes from real backend
    responses.

## 5. Non-goals and technical constraints

### 5.1 No universal Chrome navigation interception claim

The supplied PRD and SRS explicitly note that Chrome Manifest V3 does
not provide a general synchronous callback that can pause every
navigation, analyse the URL remotely, and then decide whether to
continue.

Therefore:

-   Implement interception for eligible HTTP/HTTPS anchor clicks in
    supported webpages using a content script.
-   Use an extension-controlled interstitial or equivalent extension UI
    while analysis is pending.
-   Implement SearchGuard on supported Google search result pages.
-   Investigate Declarative Net Request only for applicable rule-based
    blocking; it is not a replacement for arbitrary per-navigation
    backend analysis.
-   Address-bar navigation, bookmarks, browser UI navigation, some
    redirects, downloads, and navigation initiated outside supported
    page contexts may not be interceptable before the first request
    using the chosen MV3 design.
-   Do not state that every URL typed into Chrome's address bar is
    guaranteed to be blocked and checked before navigation unless that
    behaviour is genuinely implemented and tested.
-   Explain coverage limitations accurately in product documentation and
    settings/help UI.

### 5.2 Frontend/backend communication

The Chrome Extension should call the backend API directly for its
security decisions. The React dashboard should call the backend API
directly for manual scans, history, and reports.

Do not route extension scan requests through the dashboard website
merely to create an unnecessary extra hop. The dashboard is a user
interface, not a backend proxy.

``` text
Supported webpage link click
          |
          v
Chrome content script intercepts eligible click
          |
          v
Extension-controlled analysis/interstitial UI
          |
          v
Extension sends URL to AEGIS backend API
          |
          v
Backend runs detection and deterministic policy
          |
          v
Backend returns verdict + evidence + action
          |
          v
Extension validates response and applies policy
     /          |             \
   SAFE      SUSPICIOUS       CRITICAL
    |             |               |
Allow original   Warn; offer     Keep blocked;
destination      Proceed at       no proceed action
                 Own Risk / Cancel
```

Manual dashboard scan:

``` text
User pastes URL in React dashboard
          |
          v
Frontend validates basic input format
          |
          v
POST /api/v1/analyze
          |
          v
Backend response
          |
          v
Frontend displays real scan result
```

Google SearchGuard:

``` text
Google search results page
          |
          v
Extension identifies eligible organic results
          |
          v
Normalize + deduplicate URLs
          |
          v
POST /api/v1/analyze/batch
          |
          v
Backend returns per-URL status/verdict
          |
          v
Extension attaches matching security badges
```

The extension must still perform the supported navigation protection
check when a user clicks a search result. A search badge is not a
substitute for a navigation-time check.

## 6. Brand identity and visual design system

### 6.1 Design direction

Use a **minimal, premium, modern cybersecurity aesthetic**. The main
website must not look like a crowded SOC console. The first screen
should communicate one clear action: paste a URL and check it.

The visual language should combine:

-   White and very light cool-grey surfaces.
-   Deep navy and dark blue as the primary brand colours.
-   Restrained royal-blue accents for primary actions and focus states.
-   Clear typography and generous spacing.
-   Subtle borders, restrained shadows, and carefully used motion.
-   High-contrast status indicators that use labels and icons as well as
    colour.

Suggested starting palette (adjust only if the UI UX Pro Max analysis
identifies a stronger accessible system):

  Token       Suggested value   Usage
  ----------- ----------------- ------------------------------------------
  Navy 950    `#071B3A`         Brand backgrounds, strong contrast areas
  Navy 900    `#0B2447`         Headers, dark surfaces
  Blue 700    `#1D4ED8`         Primary action and interactive accents
  Blue 100    `#DBEAFE`         Soft information backgrounds
  White       `#FFFFFF`         Main surfaces
  Slate 50    `#F8FAFC`         App background
  Slate 200   `#E2E8F0`         Borders
  Slate 600   `#475569`         Secondary text
  Slate 900   `#0F172A`         Main text

Use semantic status tokens, but never rely on colour alone:

-   Safe: green with a shield/check icon and the text "Safe".
-   Suspicious: amber with a warning icon and the text "Suspicious".
-   Critical: red with a blocked/shield-alert icon and the text
    "Critical".
-   Checking: blue/neutral with a spinner and the text "Checking".
-   Unable to verify: neutral/amber with an information icon and
    explicit text.

### 6.2 Typography

Use a clean, highly legible sans-serif typeface such as Inter or a
comparable locally bundled/system fallback. Establish a consistent scale
for page titles, section headings, body text, labels, and metadata.
Avoid excessive uppercase text and overly wide letter spacing in body
copy.

### 6.3 Logo and emblem

Create a reusable AEGIS logo asset set:

-   Primary shield emblem.
-   Wordmark lockup.
-   Monochrome white version for dark backgrounds.
-   Navy version for light backgrounds.
-   Small icon version for extension toolbar/popup.

The emblem should communicate protection and phishing detection without
becoming visually complicated. Use a shield as the protection metaphor
and a simple central geometric/scan motif to suggest identification.
Deliver the logo as editable SVG where possible; do not rely only on a
raster image.

## 7. Preloader / splash screen

### 7.1 Visual requirement

Create a restrained, Mac-inspired startup screen. The requested visual
direction is a **white loading screen with a dark navy AEGIS
emblem/wordmark** and a slim progress indicator. The logo should be
centered, with generous whitespace and no clutter.

The earlier dark-navy/white-logo concept may be retained as an alternate
brand treatment, but the preferred production direction for this screen
is white background with navy logo.

### 7.2 Behaviour

1.  Show the splash immediately while the app initializes.
2.  Fade in the AEGIS emblem and wordmark.
3.  Show a slim, smooth progress indicator.
4.  Complete initialization and transition to the main application.
5.  Do not hold the user on an artificial timer if initialization has
    already completed.
6.  Respect reduced-motion preferences.
7.  If essential application initialization fails, transition to a
    useful error state rather than leaving an endless loader.

The preloader is for the web application. Extension popup and
interstitial pages should use lightweight loading states appropriate to
their shorter lifecycle.

## 8. Website information architecture

Create the following routes/views:

  -----------------------------------------------------------------------
  Route/view              Purpose                 Priority
  ----------------------- ----------------------- -----------------------
  `/`                     Minimal URL scanner     P0
                          homepage                

  `/scan/:scanId`         Scan progress and       P0
                          result                  

  `/history`              Real scan history from  P1
                          backend                 

  `/history/:scanId`      Detailed historical     P1
                          scan report             

  `/settings`             Backend connection,     P1
                          extension status,       
                          privacy and coverage    
                          information             

  Not found               Helpful unknown-route   P1
                          page                    
  -----------------------------------------------------------------------

If no authentication is implemented by the backend, do not imply that
history is securely separated between multiple users. Follow the
backend's actual session/history model.

## 9. Homepage UI requirements (P0)

### 9.1 Layout

Keep the homepage exceptionally simple:

1.  Compact header with AEGIS logo.
2.  Optional small navigation links: Home, Scan History, Settings.
3.  Centered headline, such as "Browse with confidence."
4.  One concise supporting sentence explaining that AEGIS checks links
    for phishing and malicious activity.
5.  A prominent URL input area.
6.  One primary "Check URL" button.
7.  A small privacy/connection note only when it communicates useful,
    accurate information.
8.  Minimal footer with product identity and relevant links.

Do not place fabricated counters, fake recent scans, sample threat
statistics, fake testimonials, or decorative data cards on the homepage.

### 9.2 URL input

-   Accept only HTTP and HTTPS URL input for analysis.
-   Provide a clear placeholder such as `https://example.com`.
-   Support paste, keyboard submission, and the primary button.
-   Trim surrounding whitespace.
-   Perform basic client-side format validation for immediate feedback.
-   Do not claim a URL is safe based on client-side validation.
-   Prevent duplicate submissions while a scan request is pending.
-   Show a clear validation message for malformed or unsupported input.
-   Do not silently rewrite the destination URL in a way that changes
    its meaning.
-   Do not store the entered URL in browser local storage unless
    explicitly required and documented.

### 9.3 Submit behaviour

On submission:

1.  Call the real `POST /api/v1/analyze` endpoint.

2.  Send the agreed request shape:

    ``` json
    {
      "url": "https://example.com",
      "source": "dashboard"
    }
    ```

3.  Display an immediate, accessible loading state.

4.  Handle pending, completed, partial, failed, timeout, and
    malformed-response conditions.

5.  On a valid response, render the actual verdict and evidence.

6.  If the backend is unavailable, show "Unable to connect to AEGIS" or
    an equivalent clear state. Never show a fabricated result.

## 10. Scan progress and result experience (P0)

### 10.1 Progress screen

The progress view should reassure the user that analysis is underway
without inventing provider outcomes.

-   Show the submitted URL in a safely truncated display, with a way to
    inspect the full value.
-   Show "Analysing URL".
-   Show only provider statuses actually returned by the backend.
-   Possible provider rows include ML analysis, Google Safe Browsing,
    VirusTotal, RDAP (if included in the backend response),
    DomainShield, and AI explanation.
-   Each provider row must distinguish `pending`, `completed`,
    `no_match`, `unavailable`, `timeout`, and `error` where those
    statuses are returned.
-   Do not animate a provider into a completed state unless the backend
    confirms completion.
-   If the API is synchronous, use the returned response state; if the
    backend later introduces asynchronous polling, follow its documented
    status endpoint.

### 10.2 Result hierarchy

The result page should use this order:

1.  Verdict and clear action-oriented headline.
2.  Risk score only if the backend supplies it.
3.  Short backend-provided reason/summary.
4.  Required user action, if any.
5.  Evidence summary by detection source.
6.  DomainShield lookalike finding and verified official-domain
    suggestion, if returned.
7.  AI-generated explanation, clearly labelled as an explanation and not
    the security authority.
8.  Scan metadata such as timestamp and scan ID where available.

### 10.3 SAFE result

-   Prominent Safe label and shield/check icon.
-   Clear explanation from backend.
-   Show relevant evidence and provider completion statuses.
-   Do not imply a guarantee of safety; use careful language such as "No
    configured threat indicators were detected."
-   If the backend says the scan is incomplete or insufficient, do not
    render Safe.

### 10.4 SUSPICIOUS result

-   Prominent Suspicious label and warning icon.
-   Explain exactly why the backend classified it as suspicious.
-   Show relevant evidence and uncertainty.
-   If this is an extension navigation interstitial, show two deliberate
    actions:
    -   **Proceed at Own Risk**
    -   **Go Back / Cancel**
-   The proceed action must require an explicit user click; never
    auto-proceed.
-   Record the user's decision through the agreed backend decision
    endpoint when available.
-   In the dashboard's manual scan result, explain the warning. Do not
    navigate the user's current tab merely because a manual scan
    completed.

### 10.5 CRITICAL result

-   Prominent Critical / Malicious warning.
-   Clearly state that the destination is blocked in the supported
    extension flow.
-   Explain the reason using backend evidence.
-   Show relevant detection-source details.
-   **Do not display a "Proceed at Own Risk", "Continue", or equivalent
    bypass action.**
-   Provide a safe action such as "Return to safety" or "Close this
    warning".
-   Never create a frontend override that contradicts a backend `BLOCK`
    action.

### 10.6 INSUFFICIENT_EVIDENCE / PENDING / ERROR

These are not Safe verdicts.

-   Explain that AEGIS could not complete enough checks to verify the
    destination.
-   Identify unavailable providers when the backend supplies that
    information.
-   Offer retry where appropriate.
-   For extension navigation, follow the backend/policy contract and
    conservative fail-safe behaviour; do not silently navigate as though
    Safe.
-   Distinguish a network error from a malicious verdict.

## 11. Detailed threat report UI

The detailed report must accommodate all information the backend may
return without overwhelming the user.

### 11.1 URL overview

-   Original URL (safely displayed).
-   Normalized hostname/domain if returned.
-   Verdict, action, risk score if supplied.
-   Scan timestamp and scan ID.
-   Copy URL control where appropriate.

### 11.2 Detection source evidence

Use compact expandable sections/cards for:

-   ML detector: prediction, supported confidence, model version,
    feature information if returned.
-   Google Safe Browsing: status, threat match, threat category/metadata
    if returned.
-   VirusTotal: malicious, suspicious, harmless, undetected counts and
    analysis status if returned.
-   RDAP/domain intelligence: registration date, domain age, registrar,
    expiration, domain status, nameservers, and public registrant
    information only if the backend supplies it.
-   DomainShield: possible brand match, similarity, transformation
    indicators, verified official domain if available.
-   AI explanation: summary, reasons, and uncertainties.

Never manufacture missing fields. If a field is absent, either omit it
or clearly display "Not available" only when that accurately reflects
the response contract.

### 11.3 Similar legitimate domain

If DomainShield returns a verified official-domain suggestion:

-   Display it in a separate "Possible legitimate alternative" section.
-   Label it as a suggestion, not a confirmed redirect.
-   Make the official domain clickable only when it is supplied by the
    trusted backend mapping.
-   Do not invent an official domain or derive one from similarity.
-   Do not automatically redirect the user.

## 12. Scan history (P1)

History must be populated exclusively by the real backend history
endpoint.

-   Show a useful empty state when there are no records.
-   Show loading, error, and retry states.
-   Display only fields returned by the backend: URL/domain, verdict,
    timestamp, risk score, scan ID, and status as available.
-   Provide search/filter controls only when they operate on actual
    returned records.
-   Support filtering by verdict where possible.
-   Allow a row to open the corresponding real scan detail.
-   Do not seed the table with sample entries.
-   Do not show fake aggregate statistics.
-   If history is not implemented by the backend yet, show a clear
    unavailable state rather than a mock history screen.

## 13. Settings and system status (P1)

Settings may include:

-   Backend connection status based on a real health check.
-   Extension installation/connection guidance where detectable.
-   Supported browser coverage and known limitations.
-   Privacy and URL handling explanation.
-   Motion/accessibility preferences only if implemented.
-   Application version/build information.

Do not show fake "All systems operational" status. A status indicator
must be based on a real health endpoint or actual runtime state.

## 14. Chrome Extension requirements

### 14.1 Technology and structure

Use Chrome Manifest V3. Keep extension logic separate from the React
dashboard. Use React for popup/interstitial UI where useful, but keep
content scripts lightweight and compatible with the extension runtime.

Suggested structure:

``` text
extension/
├── manifest.json
├── public/
│   └── icons/
├── src/
│   ├── background/
│   │   └── service-worker.ts
│   ├── content/
│   │   ├── navigation-guard.ts
│   │   └── search-guard.ts
│   ├── popup/
│   │   ├── Popup.tsx
│   │   └── main.tsx
│   ├── interstitial/
│   │   ├── Interstitial.tsx
│   │   └── main.tsx
│   ├── services/
│   │   ├── api-client.ts
│   │   ├── scan-service.ts
│   │   └── decision-service.ts
│   ├── types/
│   │   └── api.ts
│   └── styles/
├── package.json
├── tsconfig.json
└── README.md
```

This is a suggested structure; simplify if necessary while preserving
clear separation of responsibilities.

### 14.2 Manifest and permissions

-   Use Manifest V3.
-   Request only permissions required for the implemented functionality.
-   Restrict host permissions where practical and explain why each is
    needed.
-   Do not request broad permissions without a concrete feature
    requirement.
-   Keep all provider API secrets out of the extension.
-   Document how to load the unpacked extension in Chrome developer
    mode.

### 14.3 Navigation Guard

For eligible supported webpage anchor clicks:

1.  Detect an eligible HTTP/HTTPS link.
2.  Ignore in-page anchors, JavaScript URLs, browser-internal URLs,
    downloads, and unsupported link types as appropriate.
3.  Prevent the default click navigation while the supported check runs.
4.  Associate the scan with the correct tab/navigation context to avoid
    race conditions.
5.  Open an extension-controlled interstitial or controlled warning UI.
6.  Send the destination URL directly to `POST /api/v1/analyze` with
    source `chrome_extension`.
7.  Validate the response schema and verdict.
8.  Apply the action:
    -   `SAFE` + `ALLOW`: navigate to the original destination.
    -   `SUSPICIOUS` + `WARN`: show reason and explicit Proceed at Own
        Risk / Cancel.
    -   `CRITICAL` + `BLOCK`: keep destination blocked; no proceed
        control.
    -   `INSUFFICIENT_EVIDENCE`, pending, malformed response, or backend
        failure: show unable-to-verify state and follow conservative
        fail-safe policy; never treat as Safe.
9.  Ensure the same intercepted click cannot trigger duplicate scans or
    multiple navigations.
10. Record Suspicious user decisions through `POST /api/v1/decisions` if
    the endpoint is available.

Do not trust verdicts supplied by the webpage. Only accept validated
responses from the configured backend.

### 14.4 Extension popup

The popup should be compact and useful:

-   AEGIS logo and protection state based on actual extension state.
-   A short "Check a URL" input if feasible.
-   Button/link to open the dashboard.
-   Most recent real scan only if available from a real source.
-   Clear backend connection/error state.
-   Link to help/coverage explanation.

Do not invent recent scan information or claim protection is active if
the extension cannot confirm its state.

### 14.5 Extension interstitial

The interstitial is a critical security surface. It must:

-   Clearly identify the destination hostname.
-   Show "Checking this link" while analysis is pending.
-   Show the final verdict and reason.
-   Make the next action unmistakable.
-   Provide Proceed at Own Risk only for Suspicious.
-   Never provide a proceed bypass for Critical.
-   Provide Cancel/Return to safety.
-   Handle backend timeout, malformed response, tab closure, and stale
    responses.
-   Avoid displaying untrusted page content or executing scripts from
    the destination.


## 14.6 Loop prevention and approved-navigation handling (P0 — mandatory)

The extension must prevent a successful Safe decision from causing the same destination to be intercepted and analysed repeatedly.

**Required behaviour:**

1. When an eligible link is intercepted, create a unique navigation-attempt identifier and associate it with the tab, original destination, and scan.
2. Keep the original navigation paused while the extension obtains the backend result.
3. If the backend returns `SAFE` with the permitted `ALLOW` action, register a short-lived, one-time approval for that exact destination and intended tab/navigation attempt.
4. Resume navigation to the original destination.
5. When the resumed navigation is observed by the extension, match it against the one-time approval and consume that approval. Do not intercept it again and do not start another scan for that same navigation.
6. Scope the approval narrowly: exact normalized destination (while preserving the original URL for navigation), intended tab, one use, and short expiry. Do not create a broad allowlist entry for the entire domain.
7. If the approval expires, is consumed, or does not match the destination/tab, it must not authorize a different navigation.
8. Handle duplicate clicks, multiple tabs, redirects, tab closure, stale scan responses, and rapid repeated navigation without allowing an old approval to authorize a new destination.
9. A redirect to a different destination is a new navigation and must be evaluated where the implemented extension hooks support it. Do not reuse the original destination's approval for a different redirect target.
10. Keep this one-time navigation approval mechanism separate from the URL analysis cache. A cache hit may allow reuse of a recent analysis result; the one-time approval prevents the extension from re-intercepting its own resumed navigation.

**Implementation guidance:** Use extension-owned state with an appropriate short-lived lifecycle (for example, `chrome.storage.session` or carefully managed service-worker state) and unique attempt IDs. Validate messages between content scripts, service worker, and extension pages. Do not rely on a page-controlled query parameter or webpage-set flag to bypass protection.

**Cached Safe behaviour:** If the extension has a valid, unexpired cached Safe result for the exact normalized URL and current model/policy version, it may allow the supported navigation immediately without showing the interstitial, subject to the backend cache contract and policy. The one-time approval mechanism is still required so the resumed navigation is not intercepted in a loop. If there is no valid cache entry, request fresh backend analysis.

**Failure behaviour:** If approval state cannot be safely matched, do not silently treat an unrelated navigation as approved. Fall back to the normal supported analysis flow or configured unable-to-verify fail-safe behaviour.

## 14.7 Verdict-specific user experience (P0 — mandatory)

- **SAFE + ALLOW:** Show a concise Safe result if the user is already viewing the analysis screen. In the normal intercepted-link flow, proceed to the original destination without unnecessary extra confirmation. Do not interrupt the user with a second scan if a valid cached Safe result is available. Do not promise that a site is guaranteed harmless.
- **SUSPICIOUS + WARN:** Always show why the URL is suspicious using the actual backend-provided reason and available evidence. In the extension interstitial, require an explicit choice: “Proceed at Own Risk” or “Go Back”. Never auto-proceed.
- **CRITICAL + BLOCK:** Always explain why the destination is considered malicious/critical using the actual backend-provided reason and evidence. Keep the destination blocked. Do not show a “Proceed at Own Risk”, “Continue”, or equivalent bypass action.
- **INSUFFICIENT_EVIDENCE / ERROR:** Explain that AEGIS could not verify the URL. Identify unavailable providers when the backend supplies that information. Never label this state Safe or silently treat a provider failure as a clean result.

The frontend must not invent explanations. If the backend supplies no human-readable reason, display a truthful generic message and coordinate with the backend developer to include reason fields.

## 14.8 URL analysis cache integration (P0 — mandatory)

Use the caching approach already defined in the supplied AEGIS PRD/SRS: backend-managed in-memory TTL cache (the source PRD suggests `cachetools.TTLCache`) rather than Firebase as a replacement database/cache architecture.

The frontend and extension must integrate with the backend cache behaviour; they must not create an independent, authoritative client-side verdict cache.

Suggested initial TTLs from the source PRD:

| Verdict/result | Suggested backend cache policy |
|---|---|
| Safe | 15 minutes |
| Critical | 24 hours, with revalidation strategy |
| Suspicious | 1–5 minutes |
| Insufficient Evidence / provider failure | Do not cache as Safe; only short-lived negative caching may be considered |

These are prototype suggestions, not immutable security guarantees. The backend developer owns implementation and final policy. Cache identity/invalidation should account for normalized URL and relevant model/policy version. Expired or invalidated results must trigger fresh analysis.

**Frontend/extension rules:**

- Do not assume a result is cached unless the backend returns or documents a cache-hit indication, or provides a defined cache lookup contract.
- Do not store a permanent Safe verdict in `localStorage` or extension storage.
- Do not allow a cached result for one URL to authorize another URL.
- Do not treat unavailable or failed checks as a cached Safe result.
- Respect cache expiry and model/policy version changes.
- Keep one-time approved-navigation state separate from the backend analysis cache.

## 15. SearchGuard --- Google search results

### 15.1 Scope

Initially support Google Search result pages in Chrome. SearchGuard
should inspect eligible organic search results, not every arbitrary link
on the page.

### 15.2 Behaviour

1.  Detect eligible organic result containers.
2.  Extract destination URLs carefully, resolving supported Google
    redirect wrappers where practical.
3.  Exclude advertisements, navigation links, internal Google links, and
    unsupported result types where identifiable.
4.  Normalize and deduplicate URLs.
5.  Submit unique URLs in bounded batches to
    `POST /api/v1/analyze/batch` with source `search_guard`.
6.  Match each response to the correct result.
7.  Add an accessible badge next to the corresponding result.
8.  Use `MutationObserver` to detect newly inserted/dynamically loaded
    results.
9.  Avoid duplicate badges and duplicate requests.
10. Do not block or break Google Search functionality.
11. Re-check the URL through Navigation Guard when a supported search
    result is clicked.

### 15.3 Badge states

  State              Required presentation
  ------------------ ------------------------------------------------
  Checking           Neutral/blue badge with spinner and "Checking"
  Safe               Green icon + "Safe"
  Suspicious         Amber icon + "Suspicious"
  Critical           Red icon + "Critical"
  Unable to verify   Neutral/amber icon + "Unable to verify"

Badges must include accessible text and must not rely on colour alone.
Keep badge size compact and avoid obscuring result titles, snippets, or
controls.

### 15.4 Batch and performance rules

-   Deduplicate by normalized URL.
-   Use bounded concurrency and sensible batch sizes.
-   Do not submit the same URL repeatedly because of DOM mutations.
-   Handle partial batch results independently.
-   Do not mark a URL Safe if its result is missing, failed, or
    unavailable.
-   Do not fabricate badge states to make the search page look complete.

## 16. Frontend architecture and project structure

Suggested repository layout:

``` text
AEGIS/
├── frontend/
│   ├── public/
│   │   └── assets/
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   ├── scanner/
│   │   │   ├── verdict/
│   │   │   ├── evidence/
│   │   │   └── layout/
│   │   ├── pages/
│   │   ├── services/
│   │   │   ├── api-client.ts
│   │   │   ├── scan-service.ts
│   │   │   └── history-service.ts
│   │   ├── hooks/
│   │   ├── types/
│   │   ├── utils/
│   │   ├── styles/
│   │   └── main.tsx
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── extension/
│   └── [Chrome Manifest V3 implementation]
└── backend/
    └── README.md or .gitkeep only; backend implementation is owned by another developer
```

### 16.1 Frontend engineering requirements

-   Use TypeScript strict mode.
-   Define shared, explicit API response types based on the backend
    contract.
-   Centralize base URL configuration and HTTP error handling.
-   Use a small, consistent component system.
-   Keep business logic out of presentational components.
-   Use React Router or an equivalent routing solution.
-   Use Framer Motion for restrained transitions, not constant
    decorative animation.
-   Respect `prefers-reduced-motion`.
-   Ensure keyboard navigation and visible focus states.
-   Use semantic HTML and accessible labels.
-   Avoid unnecessary dependencies.
-   Keep extension build output separate from website build output.

### 16.2 API client

The frontend and extension must use configurable backend base URLs.
Local development may use a developer-configured local API URL, but no
secret keys may be stored in frontend or extension configuration.

Suggested endpoints from the supplied PRD/SRS:

  Method   Endpoint                      Purpose
  -------- ----------------------------- -----------------------------------
  POST     `/api/v1/analyze`             Analyse one URL
  POST     `/api/v1/analyze/batch`       Analyse Google search result URLs
  GET      `/api/v1/status/{scan_id}`    Check scan status
  GET      `/api/v1/verdict/{scan_id}`   Retrieve final verdict
  GET      `/api/v1/history`             List scan history
  GET      `/api/v1/history/{scan_id}`   Retrieve scan details
  POST     `/api/v1/decisions`           Record Suspicious user decision
  GET      `/api/v1/health`              Backend health check

Use only endpoints actually implemented by the backend. If the backend
developer changes the contract, update typed interfaces in coordination
rather than inventing a new API.

### 16.3 Expected analyze request

``` json
{
  "url": "https://example.com",
  "source": "dashboard"
}
```

For extension scans, use `source: "chrome_extension"`. For SearchGuard
batches, use `source: "search_guard"` in the batch request.

### 16.4 Response handling

The supplied specifications describe fields such as:

-   `scan_id`
-   `status`
-   `verdict`
-   `risk_score`
-   `action`
-   `reason`
-   `checks`
-   `domain_impersonation`

The exact response schema must be agreed with the backend developer.
Frontend types must reflect the implemented schema. Treat optional
fields as optional. Do not fabricate missing values.

## 17. Motion and interaction principles

Use Framer Motion for:

-   Splash logo/wordmark entrance.
-   Splash-to-home transition.
-   Subtle page transitions.
-   Scanner loading indicator.
-   Expand/collapse of evidence sections.
-   Verdict panel entrance.
-   Small hover/focus feedback.

Avoid:

-   Long intro animations that delay scanning.
-   Excessive parallax or animated backgrounds.
-   Motion that makes security status harder to understand.
-   Progress animations that imply backend progress not actually
    reported.
-   Motion that ignores reduced-motion preferences.

## 18. Responsive design

The website must work at desktop, laptop, tablet, and mobile widths.

-   Prioritize the URL scanner on mobile.
-   Keep input and primary action easy to use with touch.
-   Stack evidence panels vertically on narrow screens.
-   Avoid horizontal scrolling for ordinary content.
-   Keep critical warning actions visible without requiring excessive
    scrolling.
-   Ensure the extension popup fits its constrained viewport.
-   Ensure interstitial content is readable at common laptop and
    mobile-sized browser windows.

## 19. Accessibility and usability

-   Meet WCAG 2.1 AA as the target.
-   Provide sufficient text/background contrast.
-   Use labels and icons as well as status colours.
-   Ensure all controls are keyboard accessible.
-   Use visible focus rings.
-   Use appropriate heading hierarchy.
-   Announce scan state changes accessibly (for example, `aria-live` for
    status messages).
-   Do not use colour alone to communicate verdicts.
-   Use clear, plain-language explanations.
-   Make dangerous actions deliberate and visually distinct.
-   Do not make the Suspicious proceed action look like the primary safe
    action.
-   Do not offer a proceed action for Critical.

## 20. Error, empty, and edge states

Implement real UI states for:

-   Invalid URL.
-   Unsupported URL scheme.
-   Scan in progress.
-   Backend unavailable.
-   Request timeout.
-   Rate limit or provider-unavailable result returned by backend.
-   Partial analysis.
-   Insufficient evidence.
-   Malformed or unexpected API response.
-   Empty scan history.
-   History endpoint unavailable.
-   No verified DomainShield alternative.
-   Extension permission missing.
-   Unsupported navigation context.
-   Search result extraction failure.
-   SearchGuard batch partial failure.
-   Duplicate submission.
-   User cancels a Suspicious navigation.

Never convert an error state into Safe. Never fill an empty state with
fabricated examples.

## 21. Privacy and security requirements

-   Keep Google Safe Browsing, VirusTotal, and Anthropic credentials
    exclusively on the backend.
-   Do not store raw URL history in local storage unless required and
    approved.
-   Do not log full sensitive URLs unnecessarily.
-   Avoid sending cookies, credentials, or page contents to the
    dashboard/backend.
-   Treat URL text and backend-returned text as untrusted content;
    render as text, not executable HTML.
-   Validate extension message origins and message shapes.
-   Use HTTPS for deployed backend communication.
-   Configure CORS on the backend side with the backend developer.
-   Do not allow a webpage to forge a verdict or trigger privileged
    extension actions.
-   Do not use `dangerouslySetInnerHTML` for untrusted content.
-   Do not automatically navigate to a DomainShield suggested domain.

## 22. Testing and acceptance criteria

### 22.1 Website acceptance

-   Homepage loads with the intended minimal AEGIS design.
-   URL input accepts valid HTTP/HTTPS URLs and rejects invalid input
    clearly.
-   Submit invokes the real backend endpoint.
-   Loading state appears immediately.
-   Real Safe, Suspicious, Critical, and insufficient-evidence responses
    render correctly.
-   Critical has no proceed action.
-   Suspicious has explicit Proceed at Own Risk and Cancel actions in
    the extension flow.
-   Evidence fields render only when supplied.
-   History is populated only by real API data.
-   Backend unavailable state is clear and never shows fake scan
    success.
-   Layout works on desktop and mobile.
-   Keyboard and reduced-motion behaviour are tested.

### 22.2 Extension acceptance

-   Manifest V3 extension loads in Chrome developer mode.
-   Permissions are limited and documented.
-   Eligible supported link clicks are intercepted.
-   Destination does not load while supported analysis is pending.
-   Extension calls the backend directly.
-   Safe allows the original destination in the supported flow.
-   A Safe navigation resumed by the extension is not intercepted again for the same attempt; no infinite scan/navigation loop occurs.
-   A valid cached Safe result may be reused according to backend TTL and version rules, without creating a permanent client-side allowlist.
-   Suspicious always shows the backend-provided reason and explicit Proceed at Own Risk / Cancel.
-   Critical always shows the backend-provided reason, remains blocked, and has no proceed bypass.
-   Backend failure or malformed response shows unable-to-verify, not
    Safe.
-   Duplicate clicks and stale responses do not cause multiple
    navigations.
-   SearchGuard annotates eligible Google organic results.
-   Dynamic results are processed without duplicate badges or requests.
-   Search page remains usable.
-   Clicking a search result still invokes navigation protection where
    supported.
-   Address-bar and redirect coverage limitations are documented and
    tested honestly.

### 22.3 No-mock-data acceptance

-   Search the codebase for seeded scan records, hardcoded verdict
    examples, fake statistics, fake provider responses, demo scan data,
    and mock API services.
-   Remove any such implementation.
-   Use real backend calls or explicit loading/error/empty states only.
-   Automated tests may use test fixtures inside test files, but those
    fixtures must never be wired into the production UI or presented as
    live product data. If the instruction is interpreted as prohibiting
    even test fixtures, coordinate before introducing them; production
    must remain entirely free of mock data.

### 22.4 Quality bar

The interface should be polished, consistent, responsive, and free of
known blocking defects at handoff. Run linting, type checking,
production builds, unit/component tests, and real Chrome manual tests.
Document anything that cannot be verified because the backend is not yet
available.

## 23. Delivery phases

### Phase 1 --- Foundation

-   Create the three top-level folders.
-   Keep backend empty.
-   Initialize React/Vite/TypeScript/Tailwind frontend.
-   Initialize Manifest V3 extension project.
-   Apply UI UX Pro Max guidance.
-   Define shared API types and configuration.

### Phase 2 --- Website core

-   Build splash screen.
-   Build minimal homepage URL scanner.
-   Build loading, validation, error, and verdict states.
-   Integrate real `/api/v1/analyze` call.

### Phase 3 --- Extension core

-   Build popup.
-   Build supported link interception.
-   Build extension interstitial.
-   Implement Safe, Suspicious, Critical, and unable-to-verify actions.
-   Integrate real backend calls.

### Phase 4 --- SearchGuard

-   Detect eligible Google organic results.
-   Batch and deduplicate URLs.
-   Render accessible badges.
-   Handle dynamic results.

### Phase 5 --- Reports and history

-   Build detailed evidence report.
-   Build history list and detail page using real endpoints.
-   Build settings/health/coverage page.

### Phase 6 --- Validation and handoff

-   Run quality checks.
-   Test real Chrome flows.
-   Verify no production mock data exists.
-   Document API contract assumptions and browser coverage limitations.
-   Leave backend implementation untouched.

## 24. Final Antigravity instruction

Build AEGIS as a real, backend-connected frontend and Chrome Manifest V3
extension. Use UI UX Pro Max. Use React, TypeScript, Tailwind CSS, and
Framer Motion for the website. Create `frontend/`, `extension/`, and
`backend/`; implement the complete frontend and extension, and leave
`backend/` empty for the backend developer.

**Do not use mock data anywhere in the production application.** Do not
fabricate scan results, provider outcomes, history, analytics, or
status. When the real backend is unavailable, show honest loading,
empty, unavailable, or error states.

Prioritize user experience, clear security decisions, accessibility,
responsive layouts, correctness, and reliable integration. Safe may
proceed, Suspicious requires an explicit informed user decision, and
Critical must remain blocked with no proceed-at-own-risk option. Follow
the supplied AEGIS PRD and SRS, and coordinate API contract questions
rather than inventing backend behaviour.

------------------------------------------------------------------------

**End of document**
