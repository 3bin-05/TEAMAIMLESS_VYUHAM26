# AEGIS --- Software Requirements Specification (SRS)

**Product:** AEGIS --- AI-Powered Phishing Detection and Browser
Protection System\
**Document type:** Software Requirements Specification\
**Standard basis:** IEEE-style SRS structure (adapted for a hackathon
MVP)\
**Version:** 1.0\
**Status:** Implementation specification\
**Date:** 30 October 2026

------------------------------------------------------------------------

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification defines the functional,
interface, data, security, performance, and operational requirements for
AEGIS. It is intended for developers, testers, project coordinators, and
hackathon evaluators.

The document specifies how the Chrome extension, React frontend, FastAPI
backend, machine-learning detector, threat-intelligence providers,
Claude analysis layer, policy engine, cache, database, SearchGuard, and
DomainShield interact.

### 1.2 Scope

AEGIS is a browser-oriented phishing protection system. It analyzes URLs
using multiple independent sources, produces a validated verdict, and
applies a browser action. It also annotates supported search results and
detects possible lookalike domains.

The primary user-facing verdicts are: - `SAFE` - `SUSPICIOUS` -
`CRITICAL`

The internal analysis state additionally includes: -
`INSUFFICIENT_EVIDENCE` - `PENDING` - `ERROR`

### 1.3 Definitions

  -----------------------------------------------------------------------
  Term                                Definition
  ----------------------------------- -----------------------------------
  Extension                           Chrome Manifest V3 browser
                                      extension

  Interstitial                        Extension-controlled page shown
                                      instead of immediately loading the
                                      destination

  Detection provider                  ML model, Google Safe Browsing, or
                                      VirusTotal

  AI analyzer                         Claude API integration that
                                      explains/correlates evidence

  Policy engine                       Deterministic component that
                                      enforces the final verdict

  SearchGuard                         Search-result URL scanning and
                                      badge module

  DomainShield                        Lookalike-domain and
                                      brand-impersonation analysis module

  Scan                                One analysis operation for a URL

  Evidence                            Structured output from a detector
                                      or intelligence source

  Cache hit                           A valid unexpired cached analysis
                                      is reused

  Official-domain mapping             Curated mapping from a brand to a
                                      verified official domain
  -----------------------------------------------------------------------

### 1.4 References and external dependencies

-   Chrome Extensions Manifest V3 documentation:
    https://developer.chrome.com/docs/extensions/develop/
-   Chrome Declarative Net Request:
    https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
-   FastAPI documentation: https://fastapi.tiangolo.com/
-   Pydantic documentation: https://docs.pydantic.dev/
-   Google Safe Browsing documentation:
    https://developers.google.com/safe-browsing
-   VirusTotal API documentation: https://docs.virustotal.com/
-   Anthropic API documentation: https://docs.anthropic.com/
-   Scikit-learn documentation: https://scikit-learn.org/stable/
-   XGBoost documentation: https://xgboost.readthedocs.io/
-   SQLAlchemy documentation: https://docs.sqlalchemy.org/
-   RapidFuzz documentation: https://rapidfuzz.github.io/RapidFuzz/
-   tldextract documentation:
    https://github.com/john-kurkowski/tldextract

External APIs, quotas, supported methods, licensing, and terms may
change. The implementation team must verify the current documentation
and account permissions before integration.

## 2. Overall Description

### 2.1 Product perspective

AEGIS consists of three main execution environments:

1.  **Browser:** Chrome extension, content scripts, background service
    worker, popup, and interstitial UI.
2.  **Application server:** FastAPI backend, orchestration, detectors,
    AI integration, policy, cache, and persistence.
3.  **External services:** Google Safe Browsing, VirusTotal, and
    Anthropic Claude API.

The React frontend provides the dashboard and may also be bundled for
extension-controlled UI pages.

### 2.2 Product functions

-   Intercept eligible browser link navigation.
-   Analyze URL with ML, Google Safe Browsing, and VirusTotal.
-   Correlate evidence with Claude.
-   Enforce final verdict through deterministic policy.
-   Allow, warn, or block supported navigation.
-   Cache previous results.
-   Store scan history and evidence.
-   Scan supported search results and add badges.
-   Detect possible typosquatting and homoglyph domains.
-   Recommend verified official domains when available.
-   Display scan history and explanations.

### 2.3 User classes

  -----------------------------------------------------------------------
  User class              Description             Main permissions
  ----------------------- ----------------------- -----------------------
  Browser user            Uses the extension      Scan URLs, view
                                                  verdicts, make
                                                  Suspicious decision

  Dashboard user          Reviews scan history    View authorized history
                                                  and scan details

  Developer/operator      Configures backend      Manage API keys, model,
                                                  logs, and policies

  Evaluator               Tests prototype         Demonstrate supported
                                                  scenarios using test
                                                  URLs
  -----------------------------------------------------------------------

Authentication is optional for the hackathon MVP. If no authentication
is implemented, the application must not imply that scan history is
securely separated between multiple users. Use a local browser/session
identifier only if its security and lifecycle are defined.

### 2.4 Operating environment

**Browser** - Google Chrome supporting Manifest V3. - Extension loaded
in developer mode for hackathon demonstration. - Permissions limited to
those required by supported functionality.

**Backend** - Python 3.x compatible with selected dependencies. -
FastAPI served by Uvicorn. - Local development environment or secured
HTTPS deployment. - Environment variables for secrets.

**Frontend** - React, TypeScript, Vite, Tailwind CSS. - Modern Chromium
browser.

**Storage** - SQLite database. - In-memory TTL cache.

### 2.5 Design constraints

-   The browser must not receive Google, VirusTotal, or Anthropic secret
    API keys.
-   The extension must use supported Manifest V3 APIs.
-   No claim of universal navigation interception is permitted without
    implementation and test evidence.
-   The ML inference pipeline must match the training pipeline.
-   Claude output is advisory and must be validated.
-   A provider timeout or error must not be interpreted as a clean
    result.
-   SearchGuard must use batching and bounded concurrency.
-   Domain similarity alone must not establish maliciousness.
-   Backend URL fetching, if introduced, must be protected against SSRF.

### 2.6 Assumptions and dependencies

-   API credentials are available and valid.
-   External provider quotas permit hackathon testing.
-   The PhishOFE model artifact and feature extraction pipeline are
    available, or training can be completed.
-   The team has a supported Chrome environment.
-   Internet access is available for external threat-intelligence and AI
    calls.
-   A curated official-domain list is prepared for the initial
    DomainShield demonstration.

## 3. System Architecture and Component Requirements

### 3.1 Component overview

  -----------------------------------------------------------------------
  Component ID            Component               Technology
  ----------------------- ----------------------- -----------------------
  CMP-01                  Browser extension       JavaScript, Chrome
                                                  Manifest V3

  CMP-02                  User interface          React, Vite,
                                                  TypeScript, Tailwind
                                                  CSS

  CMP-03                  API backend             Python, FastAPI,
                                                  Uvicorn

  CMP-04                  ML detector             Existing PhishOFE
                                                  model,
                                                  Scikit-learn/XGBoost as
                                                  applicable

  CMP-05                  Google detector         Google Safe Browsing
                                                  API

  CMP-06                  VirusTotal detector     VirusTotal API v3

  CMP-07                  AI analyzer             Anthropic Claude API

  CMP-08                  Risk/policy engine      Python

  CMP-09                  DomainShield            Python, RapidFuzz,
                                                  tldextract, idna

  CMP-10                  SearchGuard             JavaScript content
                                                  script, DOM APIs,
                                                  MutationObserver

  CMP-11                  Cache                   cachetools TTLCache

  CMP-12                  Persistence             SQLite, SQLAlchemy

  CMP-13                  Testing                 pytest and
                                                  browser-based manual
                                                  tests
  -----------------------------------------------------------------------

### 3.2 Component interaction

1.  Extension captures an eligible URL.
2.  Extension sends URL to backend.
3.  Backend validates and normalizes input.
4.  Cache checks for a reusable result.
5.  On cache miss, detection providers run concurrently where possible.
6.  DomainShield evaluates domain resemblance.
7.  Backend constructs normalized evidence.
8.  Claude produces an advisory analysis.
9.  Policy engine validates evidence and decides the verdict/action.
10. Backend stores scan and evidence.
11. Backend returns a validated response.
12. Extension displays the verdict and applies the supported action.

## 4. Detailed Functional Requirements

### 4.1 Browser Extension (CMP-01)

**EXT-FR-001 --- Extension initialization**\
The extension shall load through a valid Manifest V3 manifest.

**EXT-FR-002 --- Eligible link interception**\
The content script shall identify eligible HTTP/HTTPS anchor navigation
events in supported pages.

**EXT-FR-003 --- Pre-navigation handling**\
For supported intercepted link clicks, the content script shall prevent
the default navigation while analysis is pending and hand the
destination to the extension workflow.

**EXT-FR-004 --- Interstitial display**\
The extension shall display an extension-controlled analysis/warning
page or equivalent controlled UI.

**EXT-FR-005 --- Backend request**\
The extension shall send the URL and source context to the configured
backend endpoint.

**EXT-FR-006 --- Verdict handling**\
The extension shall validate the response shape and recognize Safe,
Suspicious, Critical, and Insufficient Evidence states.

**EXT-FR-007 --- Safe action**\
For a valid Safe verdict, the extension shall navigate to the original
URL in the intended tab, subject to the supported flow.

**EXT-FR-008 --- Critical action**\
For a Critical verdict, the extension shall not navigate to the
destination in the supported flow and shall display a clear block
message.

**EXT-FR-009 --- Suspicious action**\
For a Suspicious verdict, the extension shall display the reason and
explicit Proceed at Own Risk and Cancel actions.

**EXT-FR-010 --- User decision logging**\
The extension shall send the Suspicious user's decision to the backend.

**EXT-FR-011 --- Error state**\
If the backend fails, the extension shall show an unable-to-verify
warning and shall not silently allow the destination as Safe.

**EXT-FR-012 --- Redirect awareness**\
The extension should detect and analyze subsequent destinations where
the implemented browser hooks permit it. The implementation must test
redirect behavior and document coverage limitations.

**EXT-FR-013 --- Secret protection**\
The extension shall not contain provider API secrets.

**Implementation note:** `webNavigation` observation alone does not
provide arbitrary navigation cancellation. The team must implement and
test the selected interception strategy. Declarative Net Request may
enforce supported static/dynamic rules, but it is not a substitute for a
general synchronous URL analysis callback.

### 4.2 Backend API (CMP-03)

**API-FR-001** The backend shall expose versioned REST endpoints under
`/api/v1`.

**API-FR-002** The backend shall validate URL input using Pydantic.

**API-FR-003** The backend shall accept only supported HTTP and HTTPS
schemes for URL analysis.

**API-FR-004** The backend shall normalize URLs for comparison and cache
lookup without changing the actual navigation destination.

**API-FR-005** The backend shall assign a unique scan ID to each new
scan.

**API-FR-006** The backend shall orchestrate independent detector calls
concurrently where feasible.

**API-FR-007** The backend shall apply provider-specific timeouts and
error handling.

**API-FR-008** The backend shall return a stable response schema.

**API-FR-009** The backend shall not accept a client-provided verdict as
authoritative.

**API-FR-010** The backend shall expose a health endpoint.

### 4.3 Machine-Learning Detector (CMP-04)

**ML-FR-001** The ML detector shall load the configured model artifact
at startup.

**ML-FR-002** The detector shall load the matching preprocessing and
feature-extraction logic.

**ML-FR-003** The detector shall validate feature names, order, count,
and data types.

**ML-FR-004** The detector shall return prediction, model version, and
confidence only when supported.

**ML-FR-005** The detector shall return a structured error if required
features cannot be computed.

**ML-FR-006** The detector shall not interpret a failed inference as
Safe.

**ML-FR-007** Model evaluation shall include precision, recall,
F1-score, PR-AUC, confusion matrix, and false-positive analysis.

### 4.4 Google Safe Browsing Detector (CMP-05)

**GSB-FR-001** The detector shall submit URLs using the configured
supported Safe Browsing API method.

**GSB-FR-002** The detector shall parse threat matches and relevant
threat metadata.

**GSB-FR-003** The detector shall return a distinct no-match result and
a distinct unavailable/error result.

**GSB-FR-004** The detector shall use a backend-only API key.

**GSB-FR-005** The detector shall respect configured timeout and
provider quota constraints.

### 4.5 VirusTotal Detector (CMP-06)

**VT-FR-001** The detector shall use VirusTotal API v3.

**VT-FR-002** The detector shall handle URL submission/lookup according
to the supported API workflow.

**VT-FR-003** The detector shall handle asynchronous analysis status.

**VT-FR-004** The detector shall parse available malicious, suspicious,
harmless, and undetected statistics.

**VT-FR-005** The detector shall distinguish no detection from
unavailable or incomplete analysis.

**VT-FR-006** The detector shall protect its API key and respect
provider quotas and terms.

### 4.6 AI Analyzer (CMP-07)

**AI-FR-001** The AI analyzer shall receive a structured evidence
object.

**AI-FR-002** The analyzer shall return a constrained response
containing a recommendation and explanation.

**AI-FR-003** The backend shall validate AI output against a schema and
allowed enum values.

**AI-FR-004** The analyzer shall not receive provider secrets or
unnecessary personal data.

**AI-FR-005** The analyzer shall treat all URL-derived and
provider-derived text as untrusted input.

**AI-FR-006** AI failure shall not disable deterministic policy
evaluation.

**AI-FR-007** The AI recommendation shall not override mandatory policy
rules.

### 4.7 Risk and Policy Engine (CMP-08)

**POL-FR-001** The policy engine shall consume normalized detector
outputs.

**POL-FR-002** The policy engine shall enforce mandatory Critical rules
for configured confirmed high-confidence threat matches.

**POL-FR-003** The policy engine shall combine ML, threat-intelligence,
and DomainShield evidence using documented rules.

**POL-FR-004** The policy engine shall return Safe only when the
configured minimum evidence requirements are satisfied.

**POL-FR-005** The policy engine shall return Suspicious for unresolved
conflicting or uncertain evidence according to policy.

**POL-FR-006** The policy engine shall support internal Insufficient
Evidence.

**POL-FR-007** The policy engine shall validate and may disregard
Claude's recommendation.

**POL-FR-008** Every verdict shall include a reason code and
user-readable explanation.

**POL-FR-009** Risk score ranges and thresholds shall be configurable
and versioned.

### 4.8 SearchGuard (CMP-10)

**SG-FR-001** SearchGuard shall run on configured supported search
result pages.

**SG-FR-002** SearchGuard shall identify eligible organic result
elements.

**SG-FR-003** SearchGuard shall extract destination URLs without
treating arbitrary page links as search results.

**SG-FR-004** SearchGuard shall normalize and deduplicate extracted
URLs.

**SG-FR-005** SearchGuard shall submit URL batches to the backend.

**SG-FR-006** SearchGuard shall use bounded concurrency and backend
caching.

**SG-FR-007** SearchGuard shall add a status badge to each mapped
result.

**SG-FR-008** SearchGuard shall support Checking, Safe, Suspicious,
Critical, and Unable to Verify badge states.

**SG-FR-009** SearchGuard shall detect dynamically inserted results
using MutationObserver.

**SG-FR-010** SearchGuard shall avoid duplicate badges and duplicate
requests.

**SG-FR-011** SearchGuard shall not imply that an unchecked result is
Safe.

**SG-FR-012** SearchGuard shall not interfere with the search engine's
core behavior.

**SG-FR-013** A subsequent click shall still use the navigation
protection workflow where supported.

### 4.9 DomainShield (CMP-09)

**DS-FR-001** DomainShield shall parse the hostname and registrable
domain.

**DS-FR-002** DomainShield shall normalize internationalized domains
using IDNA-aware handling.

**DS-FR-003** DomainShield shall compare domains against a curated,
versioned official-domain mapping.

**DS-FR-004** DomainShield shall calculate one or more string similarity
signals.

**DS-FR-005** DomainShield shall detect configured character
substitutions, insertions, deletions, transpositions, homoglyphs, and
suspicious domain structures.

**DS-FR-006** DomainShield shall return possible brand/domain matches
with evidence and similarity information.

**DS-FR-007** DomainShield shall not classify a domain as malicious
solely because of string similarity.

**DS-FR-008** DomainShield shall recommend an official destination only
when the destination is present in the trusted mapping.

**DS-FR-009** DomainShield shall not automatically redirect users to a
suggested domain.

### 4.10 Cache (CMP-11)

**CACHE-FR-001** The cache shall store completed analysis results using
a normalized URL key.

**CACHE-FR-002** The cache shall apply a configurable TTL.

**CACHE-FR-003** The cache shall distinguish Safe, Suspicious, Critical,
and incomplete results.

**CACHE-FR-004** Expired entries shall not be treated as valid.

**CACHE-FR-005** Cache keys or invalidation logic shall account for
model/policy version changes.

**CACHE-FR-006** Cache failure shall not prevent a fresh analysis.

**CACHE-FR-007** Critical entries shall be revalidated according to
configured policy rather than treated as permanently authoritative.

### 4.11 Database and History (CMP-12)

**DB-FR-001** The backend shall persist completed scan metadata.

**DB-FR-002** The backend shall persist structured detection results
associated with the scan ID.

**DB-FR-003** The backend shall persist user decisions for Suspicious
scans when provided.

**DB-FR-004** The backend shall support listing and retrieving
authorized scan history.

**DB-FR-005** The backend shall record timestamps in a consistent
timezone, preferably UTC.

**DB-FR-006** The backend shall avoid storing credentials, cookies,
authorization headers, or unnecessary webpage content.

**DB-FR-007** The backend shall redact likely sensitive URL parameters
before storage and display.

**DB-FR-008** The backend shall define retention and deletion behavior.

**DB-FR-009** The browser shall never connect directly to SQLite.

## 5. External Interface Requirements

### 5.1 Browser extension interface

Required extension resources: - `manifest.json` - Background service
worker - Content script for supported link interception - Search result
content script - Popup UI - Interstitial or warning UI - Optional
Declarative Net Request rules

Permissions must be limited to those needed for the chosen
implementation. Host permissions should be restricted where practical.
The extension must disclose its scanning behavior to users.

### 5.2 Frontend interface

Main views: - Dashboard overview. - Scan history. - Scan details. -
Analysis/loading state. - Safe result. - Suspicious warning. - Critical
block page. - Unable-to-verify page. - SearchGuard badge UI. -
DomainShield explanation and official-domain suggestion.

The UI shall use accessible labels and text, not color alone.

### 5.3 Backend interface

Base URL is environment-specific. The backend shall expose JSON REST
endpoints.

#### `POST /api/v1/analyze`

Request:

``` json
{
  "url": "https://example.com",
  "source": "chrome_extension"
}
```

Response:

``` json
{
  "scan_id": "uuid",
  "status": "completed",
  "verdict": "SAFE",
  "risk_score": 8,
  "action": "ALLOW",
  "reason": "No configured threat indicators were detected and required checks completed.",
  "checks": {
    "ml": {"status": "completed", "prediction": "legitimate"},
    "google_safe_browsing": {"status": "completed", "threat_detected": false},
    "virustotal": {"status": "completed", "malicious": 0, "suspicious": 0}
  },
  "domain_impersonation": {
    "possible_match": null,
    "official_domain": null,
    "similarity": null
  }
}
```

The response is illustrative. A real Safe response must only be returned
if the configured evidence requirements were satisfied.

#### `POST /api/v1/analyze/batch`

Request:

``` json
{
  "urls": [
    "https://example.com",
    "https://another-example.com"
  ],
  "source": "search_guard"
}
```

The response shall return a per-item status and result. Partial batch
failure shall not invalidate successful items.

#### Other endpoints

  -----------------------------------------------------------------------------
  Endpoint                      Method                  Purpose
  ----------------------------- ----------------------- -----------------------
  `/api/v1/status/{scan_id}`    GET                     Scan processing status

  `/api/v1/verdict/{scan_id}`   GET                     Final verdict

  `/api/v1/history`             GET                     List authorized scan
                                                        history

  `/api/v1/history/{scan_id}`   GET                     Scan details

  `/api/v1/history/{scan_id}`   DELETE                  Delete authorized scan
                                                        if supported

  `/api/v1/decisions`           POST                    Record user decision

  `/api/v1/health`              GET                     Health check
  -----------------------------------------------------------------------------

### 5.4 External service interfaces

-   Google Safe Browsing API: URL threat lookup using configured API
    credentials.
-   VirusTotal API v3: URL lookup/submission and analysis retrieval.
-   Anthropic Claude API: structured evidence analysis.

External service adapters shall isolate provider-specific
request/response formats from the rest of the application.

## 6. Data Requirements

### 6.1 Logical data model

**Users** (optional) - `user_id` --- primary key - `created_at` -
`display_name` --- optional - Do not store unnecessary personal
information.

**URL scans** - `scan_id` --- primary key - `user_id` or session
reference --- nullable - `original_url_redacted` - `normalized_url` -
`registrable_domain` - `source` - `status` - `verdict` - `risk_score` -
`reason_code` - `model_version` - `policy_version` - `created_at` -
`completed_at`

**Detection results** - `result_id` --- primary key - `scan_id` ---
foreign key - `provider` - `provider_status` - `result_json` -
`checked_at`

**User decisions** - `decision_id` --- primary key - `scan_id` ---
foreign key - `decision` (`PROCEED`, `CANCEL`) - `decided_at`

**Brand domains** - `brand_id` - `brand_name` - `official_domain` -
`source` - `verified_at` - `mapping_version`

### 6.2 Data validation

-   URL must parse successfully.
-   Scheme must be HTTP or HTTPS.
-   Hostname must be present.
-   URL length must be limited to a configured maximum.
-   JSON fields must be schema validated.
-   Verdict and action must use enumerated values.
-   Risk score must be within the configured range.
-   Timestamps must be valid and consistent.

### 6.3 Data retention and privacy

-   Define a default retention period before public deployment.
-   Redact likely secrets in query parameters.
-   Restrict access to scan history.
-   Do not store browser cookies, credentials, or full page contents.
-   Provide a deletion path if user history is stored.
-   Logs must not contain API keys or authorization headers.

## 7. Risk Classification and Decision Logic

### 7.1 Verdicts

  -----------------------------------------------------------------------
  Verdict                 Meaning                 Browser action
  ----------------------- ----------------------- -----------------------
  SAFE                    Required checks         ALLOW
                          completed and policy    
                          found sufficiently low  
                          risk                    

  SUSPICIOUS              Uncertain, conflicting, WARN
                          or concerning           
                          indicators              

  CRITICAL                Confirmed or            BLOCK
                          sufficiently strong     
                          malicious evidence      

  INSUFFICIENT_EVIDENCE   Required checks         VERIFY / FAIL-SAFE
                          incomplete or           
                          unavailable             
  -----------------------------------------------------------------------

### 7.2 Policy precedence

The following precedence is recommended:

1.  Input validation failure: reject the scan request.
2.  Confirmed high-confidence malicious match: Critical.
3.  Other strong corroborated malicious evidence: Critical according to
    policy.
4.  Possible brand impersonation or conflicting signals: Suspicious
    unless stronger evidence exists.
5.  Required checks incomplete or unavailable: Insufficient Evidence.
6.  Safe only when all configured minimum evidence requirements are met.

The exact policy must be versioned, documented, and tested.
Provider-specific labels must be interpreted carefully; a single weak or
stale signal should not automatically be treated as definitive.

### 7.3 AI output schema

Suggested constrained output:

``` json
{
  "recommendation": "SUSPICIOUS",
  "summary": "The evidence is mixed.",
  "reasons": [
    "The ML model indicates elevated phishing risk.",
    "Threat-intelligence results are inconclusive."
  ],
  "uncertainties": [
    "One provider did not complete its check."
  ]
}
```

The backend shall validate the schema and apply deterministic policy
after receiving this response.

## 8. Security Requirements

### 8.1 Secret management

-   Store API keys in backend environment variables or a secret manager.
-   Exclude `.env` from version control.
-   Never place API keys in frontend environment variables that are
    bundled into browser code.
-   Rotate any key accidentally exposed in source control.

### 8.2 URL validation and SSRF

-   Accept only HTTP/HTTPS URLs.
-   Reject malformed URLs and unsupported schemes.
-   If the backend fetches URLs, defend against localhost, private,
    link-local, and cloud metadata addresses.
-   Revalidate DNS results and redirects to prevent DNS rebinding and
    redirect-based SSRF.
-   Set strict response-size, redirect-count, and timeout limits.
-   Prefer reputation APIs and URL feature extraction without fetching
    arbitrary pages for the MVP.

### 8.3 Browser security

-   Use extension-controlled warning pages.
-   Validate messages between content scripts, service worker, and
    extension pages.
-   Do not trust page-provided messages or verdicts.
-   Prevent duplicate navigation and race conditions.
-   Use a unique scan identifier to associate verdicts with the correct
    tab and navigation.
-   Test tab closure, rapid clicks, redirects, and stale responses.

### 8.4 AI security

-   Treat all external text as untrusted.
-   Keep the prompt focused on structured evidence analysis.
-   Do not provide secrets or user credentials.
-   Validate output and enforce policy outside the LLM.
-   Do not let instructions embedded in URLs or page content alter the
    analysis policy.

### 8.5 Abuse prevention

-   Apply request size limits.
-   Apply rate limits to public endpoints where appropriate.
-   Restrict CORS to known frontend origins.
-   Validate source and request identifiers.
-   Prevent batch endpoint abuse with maximum batch size and concurrency
    limits.

## 9. Performance and Reliability Requirements

### 9.1 Performance targets

These are prototype targets, not provider guarantees: - Backend
validation and cache lookup should complete quickly under normal local
conditions. - Independent external checks should run concurrently where
possible. - SearchGuard should avoid sending duplicate URLs. - The UI
should show a loading state immediately. - The backend should enforce
provider timeouts. - A batch should return per-URL status so one slow
provider does not hide completed results.

### 9.2 Reliability

-   External service errors must be isolated.
-   The system must distinguish no threat found from no result obtained.
-   Cache failures must fall back to fresh analysis.
-   Database write failure must be logged and surfaced appropriately
    without fabricating persistence success.
-   The extension must not mistake malformed or stale responses for
    Safe.
-   The policy engine must remain functional if Claude is unavailable.

## 10. Error Handling

  -----------------------------------------------------------------------
  Error condition                     Expected behavior
  ----------------------------------- -----------------------------------
  Invalid URL                         Return validation error; do not
                                      navigate

  ML model unavailable                Mark ML unavailable; continue other
                                      checks

  Google Safe Browsing timeout        Mark provider timeout

  VirusTotal rate limit               Mark provider limited/unavailable;
                                      do not treat as clean

  Claude API failure                  Skip AI explanation; deterministic
                                      policy continues

  Database write failure              Log and report persistence issue;
                                      preserve verdict response if safe
                                      to do so

  Backend unavailable                 Extension displays unable-to-verify
                                      warning

  Malformed backend response          Reject response; do not treat as
                                      Safe

  Search DOM changed                  Skip unsupported result; do not
                                      break search page

  Domain mapping missing              Report no verified suggestion; do
                                      not invent one
  -----------------------------------------------------------------------

## 11. Testing Requirements

### 11.1 Unit tests

-   URL parser and normalizer.
-   Feature extraction.
-   ML model loading and prediction.
-   Provider response parsing.
-   Timeout and error handling.
-   Policy precedence.
-   Cache TTL and invalidation.
-   Domain similarity and homoglyph cases.
-   Pydantic request/response validation.
-   URL redaction.

### 11.2 Integration tests

-   Backend with mocked Google Safe Browsing response.
-   Backend with mocked VirusTotal response.
-   Backend with mocked Claude response.
-   Parallel detector execution.
-   Partial provider failure.
-   Database persistence and history retrieval.
-   Batch URL analysis.
-   Cache hit and cache miss.

### 11.3 Browser tests

-   Eligible link click is intercepted in supported page.
-   Destination does not load during analysis.
-   Safe verdict allows navigation.
-   Critical verdict blocks navigation.
-   Suspicious verdict requires explicit decision.
-   Backend failure produces unable-to-verify state.
-   SearchGuard annotates eligible results.
-   Dynamic results receive badges once.
-   Search page remains usable.
-   Redirect and direct-address-bar limitations are documented.

### 11.4 DomainShield tests

Test examples should include: - Character substitution. - Character
insertion/deletion. - Transposition. - Repeated characters. - Digit
substitution. - Unicode lookalikes. - Legitimate similar domains to
measure false positives. - Unknown brands with no official mapping.

### 11.5 Security tests

-   Unsupported URL schemes.
-   Malformed URL inputs.
-   Oversized batch.
-   API key exposure checks.
-   CORS behavior.
-   SSRF test cases if URL fetching exists.
-   Prompt injection strings in untrusted evidence.
-   Forged client verdict.
-   Stale or mismatched scan ID.
-   Sensitive query parameter redaction.

## 12. Acceptance Test Scenarios

  -----------------------------------------------------------------------
  Test ID                 Scenario                Expected result
  ----------------------- ----------------------- -----------------------
  AT-001                  Known legitimate URL    Safe, if policy
                          with successful clean   evidence requirements
                          checks                  pass

  AT-002                  Confirmed malicious URL Critical and blocked

  AT-003                  Mixed or uncertain      Suspicious
                          evidence                

  AT-004                  Required providers      Insufficient Evidence,
                          unavailable             not Safe

  AT-005                  Suspicious URL, user    Destination remains
                          chooses cancel          unopened

  AT-006                  Suspicious URL, user    Explicitly recorded and
                          chooses proceed         opened in supported
                                                  flow

  AT-007                  Repeat same URL within  Cached result reused
                          TTL                     

  AT-008                  Cache entry expires     Fresh analysis occurs

  AT-009                  Search results contain  One analysis per unique
                          repeated URL            URL within the batch

  AT-010                  New search results load New eligible URLs are
                          dynamically             analyzed and tagged

  AT-011                  Lookalike domain        DomainShield returns
                          matches curated brand   possible match and
                                                  explanation

  AT-012                  Similarity exists but   No official destination
                          no reliable brand       is invented
                          mapping                 

  AT-013                  Malformed Claude        Response rejected;
                          response                policy still operates

  AT-014                  Critical Google threat  Policy returns Critical
                          match and AI says Safe  

  AT-015                  API key inspection of   No provider secret is
                          extension bundle        present

  AT-016                  Backend timeout         Extension shows
                                                  unable-to-verify state
  -----------------------------------------------------------------------

## 13. Deployment and Configuration

### 13.1 Environment variables

Example backend `.env`:

``` env
APP_ENV=development
API_HOST=127.0.0.1
API_PORT=8000

GOOGLE_SAFE_BROWSING_API_KEY=replace_me
VIRUSTOTAL_API_KEY=replace_me
ANTHROPIC_API_KEY=replace_me

DATABASE_URL=sqlite:///./aegis.db
CACHE_TTL_SAFE=900
CACHE_TTL_SUSPICIOUS=180
CACHE_TTL_CRITICAL=86400

ML_MODEL_PATH=app/models/phishing_model.joblib
```

Never commit real credentials. Use placeholders in documentation and
`.env.example`.

### 13.2 Local development

Backend:

``` bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

``` bash
cd frontend
npm install
npm run dev
```

Extension: 1. Build the frontend/extension assets if required. 2. Open
Chrome extensions management. 3. Enable Developer mode. 4. Load the
extension's unpacked build directory. 5. Configure the backend base URL
for local testing. 6. Test only with controlled URLs and test pages.

### 13.3 Configuration and deployment notes

-   Local backend is suitable for initial development.
-   A deployed extension backend must use HTTPS.
-   Configure allowed frontend origins.
-   Keep API keys only on the server.
-   Do not use production credentials in public demonstrations.
-   Provide a safe, controlled test set.

## 14. Suggested Repository Structure

``` text
AEGIS/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── routes.py
│   │   │   └── schemas.py
│   │   ├── engine/
│   │   │   ├── orchestrator.py
│   │   │   ├── risk_scorer.py
│   │   │   └── policy_engine.py
│   │   ├── detection/
│   │   │   ├── ml_detector.py
│   │   │   ├── google_safe_browsing.py
│   │   │   └── virustotal.py
│   │   ├── ai/
│   │   │   └── claude_analyzer.py
│   │   ├── domain/
│   │   │   ├── typosquatting.py
│   │   │   └── brand_domains.json
│   │   ├── search/
│   │   │   └── batch_service.py
│   │   ├── cache/
│   │   │   └── cache_manager.py
│   │   ├── database/
│   │   │   ├── connection.py
│   │   │   └── models.py
│   │   └── ml/
│   │       ├── model.joblib
│   │       └── feature_extractor.py
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── types/
│   └── package.json
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── search_guard.js
│   ├── popup/
│   └── interstitial/
├── docs/
│   ├── AEGIS_PRD.md
│   └── AEGIS_SRS.md
└── README.md
```

This is a suggested logical structure. The team may simplify it during
the hackathon, but should preserve module boundaries.

## 15. Implementation Milestones

**Milestone 1 --- Skeleton** - Repository, backend, frontend,
extension. - Health endpoint and API contract. - Basic
extension-to-backend communication.

**Milestone 2 --- Detection** - Model inference. - Google Safe
Browsing. - VirusTotal. - Normalized evidence schema.

**Milestone 3 --- Decision** - Claude integration. - Deterministic
risk/policy engine. - Verdict and action response.

**Milestone 4 --- Browser protection** - Supported link interception. -
Interstitial. - Safe, Suspicious, Critical, and insufficient-evidence
flows.

**Milestone 5 --- Intelligence additions** - Cache and history. -
SearchGuard. - DomainShield.

**Milestone 6 --- Validation** - Unit and integration tests. - Browser
tests. - Failure and bypass testing. - Demonstration preparation.

## 16. Traceability Matrix

  Product requirement          SRS requirements
  ---------------------------- ------------------------------
  Navigation protection        EXT-FR-001 to EXT-FR-013
  Multi-source URL detection   ML-FR, GSB-FR, VT-FR
  Claude analysis              AI-FR-001 to AI-FR-007
  Deterministic verdict        POL-FR-001 to POL-FR-009
  Search result badges         SG-FR-001 to SG-FR-013
  Typosquatting detection      DS-FR-001 to DS-FR-009
  Caching                      CACHE-FR-001 to CACHE-FR-007
  Scan history                 DB-FR-001 to DB-FR-009
  Secure operation             Sections 8, 9, and 10
  MVP acceptance               Section 12

## 17. Open Decisions

The following items must be confirmed by the implementation team:

1.  Exact PhishOFE model artifact, algorithm, feature schema, and
    preprocessing pipeline.
2.  Exact Chrome navigation interception coverage and behavior for
    address-bar navigation and redirects.
3.  Whether the frontend dashboard is local-only or deployed.
4.  Whether user authentication is included in the MVP.
5.  Final provider timeout, rate-limit, and retry settings.
6.  Final risk thresholds and policy version.
7.  Search result selectors and supported search engines.
8.  Initial curated brand-domain list and verification source.
9.  Database retention and URL redaction policy.
10. Whether any webpage content fetching is required; if not, keep the
    MVP URL-only.

------------------------------------------------------------------------

**End of SRS**
