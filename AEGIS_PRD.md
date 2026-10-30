# AEGIS --- Product Requirements Document (PRD)

**Product:** AEGIS --- AI-Powered Phishing Detection and Browser
Protection System\
**Document type:** Product Requirements Document\
**Version:** 1.0\
**Status:** Hackathon MVP specification\
**Target delivery:** 24-hour hackathon prototype\
**Date:** 30 October 2026

------------------------------------------------------------------------

## 1. Executive Summary

AEGIS is a browser-based, multi-layer phishing protection system
designed to help users avoid malicious, deceptive, and impersonation
websites before they interact with them.

The system combines:

1.  A Chrome browser extension that mediates supported navigation and
    presents security warnings.
2.  A URL analysis engine that evaluates URLs using a machine-learning
    model, Google Safe Browsing, and VirusTotal.
3.  An AI-assisted evidence analysis layer using the Claude API.
4.  A deterministic risk and policy engine that validates evidence and
    determines the action.
5.  A cache and database that reduce repeated analysis and preserve scan
    history.
6.  SearchGuard, which checks URLs displayed in supported search-engine
    result pages and adds security indicators.
7.  DomainShield, which identifies possible typosquatting, homoglyph,
    and brand-impersonation domains and can suggest a verified official
    domain.

AEGIS presents three primary user-facing verdicts: **Safe**,
**Suspicious**, and **Critical**. Internally, it also supports
**Insufficient Evidence** when the available checks cannot justify a
safe or malicious conclusion.

AEGIS is intended to be a defensive security product. It must minimize
exposure to untrusted pages, protect API credentials, communicate
uncertainty honestly, and avoid treating an AI-generated statement as
authoritative security evidence.

## 2. Product Vision

Make safer browsing proactive rather than reactive: identify suspicious
destinations before users interact with them, explain why a destination
is risky, and provide a clear and controlled decision path.

### 2.1 Product goals

-   Detect known phishing, malware, and unsafe URLs using reputable
    threat-intelligence sources.
-   Identify phishing patterns that may not yet appear in threat feeds.
-   Correlate independent signals to produce an understandable verdict.
-   Prevent supported navigation to Critical destinations.
-   Give users an informed choice when a destination is Suspicious.
-   Annotate supported search results with security status before the
    user clicks.
-   Identify likely lookalike domains and recommend official domains
    when reliably verified.
-   Preserve scan history and evidence for user review and product
    analytics.
-   Reduce latency and unnecessary external API calls through caching
    and batching.

### 2.2 Non-goals for the 24-hour MVP

The initial prototype does not promise:

-   Protection in every browser or every navigation path.
-   Complete protection against all phishing, malware, zero-day, or
    social-engineering attacks.
-   Full webpage crawling, script emulation, or sandbox detonation.
-   Guaranteed identification of every brand impersonation domain.
-   Enterprise endpoint management, centralized policy administration,
    or SIEM integration.
-   Production-grade multi-region availability or large-scale
    distributed processing.
-   Automatic blocking of every link in every search engine.
-   A definitive attribution of a suspicious domain to a brand or
    attacker.

## 3. Target Users and Use Cases

### 3.1 Target users

-   General web users who want warnings before visiting suspicious
    sites.
-   Students and non-specialist users who may have difficulty
    identifying deceptive URLs.
-   Security-conscious users who want scan history and explanations.
-   Hackathon evaluators who need to observe the complete detection and
    protection workflow.

### 3.2 Primary user stories

**Navigation protection** - As a user, when I attempt to open a
supported URL, I want AEGIS to analyse it before the destination page
loads so that I can avoid interacting with a malicious page. - As a
user, I want a clear Safe, Suspicious, or Critical result. - As a user,
I want to proceed only after an explicit warning when a URL is
Suspicious. - As a user, I want Critical destinations to remain blocked.

**SearchGuard** - As a user, when I view supported search results, I
want AEGIS to add a security badge beside each eligible result. - As a
user, I want to understand why a result is flagged. - As a user, I want
search scanning to avoid excessive delays and repeated API requests.

**DomainShield** - As a user, when I receive a lookalike URL such as
`facelook.example` or a domain using character substitutions, I want
AEGIS to detect the resemblance to a known brand. - As a user, I want
AEGIS to suggest a legitimate destination only when the official domain
is supported by a trusted mapping. - As a user, I want the system to
explain that similarity is a warning signal, not proof of malicious
ownership.

**History and analytics** - As a user, I want to view previously scanned
URLs, timestamps, verdicts, and risk scores. - As a user, I want to
inspect the evidence used for a verdict. - As a user, I want to see
aggregate counts of Safe, Suspicious, and Critical scans.

## 4. Product Scope and Functional Modules

### 4.1 Browser Protection

The Chrome extension is the user-facing enforcement point.

Responsibilities: - Observe supported navigation or link-click events. -
Prevent the default action for supported intercepted link clicks while
analysis is pending. - Send the destination URL to the backend. -
Display an extension-controlled interstitial or analysis page. - Receive
a validated verdict. - Allow navigation for Safe results. - Block
Critical results. - Present an explicit proceed-at-own-risk action for
Suspicious results. - Record the user's decision. - Maintain a fail-safe
state if the backend cannot provide a verdict.

**MVP browser coverage limitation:** Chrome Manifest V3 does not permit
arbitrary synchronous blocking of all navigation through every API. A
content script can intercept eligible page link clicks, while
Declarative Net Request can enforce supported block rules. Address-bar
navigation, redirects, browser-internal pages, downloads, and navigation
initiated outside covered page contexts require separate handling and
testing. The product must not claim universal pre-load interception
unless it has been demonstrated.

### 4.2 URL Intelligence Engine

The backend runs three independent detection sources.

**A. Machine-learning detector** - Load the existing PhishOFE-trained
model and its exact preprocessing pipeline. - Extract the same features
and in the same order as used during training. - Return prediction,
calibrated or otherwise appropriately labelled confidence, model
version, and feature errors. - Do not invent confidence values if the
model does not produce calibrated probabilities.

**B. Google Safe Browsing** - Submit the URL using the supported API
method and configured threat categories. - Parse match/no-match and
threat metadata. - Treat service errors and timeouts as unavailable, not
as a clean result. - Keep the API key on the backend.

**C. VirusTotal** - Submit or retrieve URL analysis using the supported
VirusTotal API v3 workflow. - Handle asynchronous analysis identifiers
and poll or retrieve the completed analysis when appropriate. - Record
malicious, suspicious, harmless, undetected, and unavailable counts when
returned. - Respect rate limits and terms of use. - Keep the API key on
the backend.

### 4.3 AI Analysis Layer

The Claude API receives a compact, structured evidence object from the
three detection mechanisms.

Responsibilities: - Summarize the evidence. - Explain agreement and
disagreement between sources. - Identify missing or inconclusive
signals. - Return a constrained structured recommendation and
explanation.

Restrictions: - Claude is advisory and is not the final security
authority. - Claude must not override mandatory policy rules for
confirmed malicious detections. - The backend must validate the model's
output against an allowed schema. - Untrusted URL data and external
analysis text must be treated as data, not instructions. - Do not send
secrets, API keys, cookies, credentials, or unnecessary personal data to
the LLM. - On LLM failure, the deterministic policy engine must still
return a safe, explainable outcome or Insufficient Evidence.

### 4.4 Risk Scoring and Policy Engine

A deterministic Python module combines source evidence and enforces
mandatory rules.

Responsibilities: - Normalize detector outputs into a common schema. -
Apply hard-block rules for confirmed high-confidence threat matches. -
Evaluate ML risk and external-source corroboration. - Account for
unavailable sources and stale evidence. - Validate the Claude
recommendation. - Produce the final verdict and browser action.

Suggested initial policy: - **Critical:** A trusted source confirms a
relevant malicious threat, or strong independent evidence meets a
documented high-risk rule. - **Suspicious:** Evidence is conflicting,
incomplete, uncertain, or indicates possible impersonation without
sufficient proof for Critical. - **Safe:** Required checks completed
successfully, no known threat was found, and the configured ML risk is
below a validated threshold. - **Insufficient Evidence (internal):**
Required services are unavailable, the model cannot evaluate the URL, or
evidence is too incomplete to justify Safe.

A similarity score by itself must not cause a Critical verdict. A
missing threat-intelligence match must not be interpreted as proof that
a URL is safe.

### 4.5 SearchGuard --- Search Result Scanner

Initial target: Google Search result pages in Chrome.

Responsibilities: - Detect eligible organic search result containers. -
Extract destination URLs, resolving supported redirect wrappers
carefully. - Exclude ads, navigation elements, internal links, and
unsupported result types where identifiable. - Normalize and deduplicate
URLs. - Submit eligible URLs to a batch analysis endpoint. - Use cache
results before requesting fresh analysis. - Apply bounded concurrency
and batch limits. - Add accessible status badges beside corresponding
results. - Handle dynamically loaded results using `MutationObserver`. -
Avoid repeated DOM decoration and duplicate requests. - Update badges
when results change or load incrementally.

Badge states: - Safe - Suspicious - Critical - Checking - Unable to
verify

SearchGuard must not block or alter search-engine functionality beyond
adding its security indicators. A badge must not imply that an
unverified URL is safe.

### 4.6 DomainShield --- Typosquatting and Impersonation Detection

Responsibilities: - Parse the registrable domain using a Public Suffix
List-aware library. - Normalize internationalized domain names safely. -
Compare the requested domain with a curated list of verified official
brand domains. - Detect common transformations such as character
insertion/deletion/substitution, transposition, digit substitution,
repeated characters, homoglyphs, and suspicious subdomain placement. -
Use string similarity algorithms such as Levenshtein distance and
Jaro-Winkler as signals. - Combine similarity with other evidence such
as threat-intelligence results, domain characteristics, and model
output. - Return candidate brand/domain matches with an explanation and
confidence or similarity score. - Recommend an official destination only
when it exists in the trusted mapping.

The initial brand-domain mapping should be curated and versioned.
Similarity alone cannot prove impersonation. Legitimate domains may
resemble one another, and attackers can use domains that do not resemble
a known brand.

### 4.7 Cache

Use an in-memory TTL cache for the hackathon prototype.

Responsibilities: - Cache completed URL analysis results. - Reduce
repeated API calls. - Support separate TTLs by verdict and evidence
freshness. - Normalize URLs before cache lookup. - Include relevant
model/policy version information in cache keys or invalidate entries
after version changes. - Avoid treating stale Safe results as
permanently safe.

Suggested prototype TTLs, subject to validation: - Safe: 15 minutes. -
Critical: 24 hours, with revalidation strategy. - Suspicious: 1--5
minutes. - Insufficient Evidence: do not cache as Safe; short-lived
negative caching may be used for service failures.

A persistent database and the cache serve different purposes. The
database stores history; the cache accelerates repeated lookups.

### 4.8 Database and History

Recommended hackathon database: SQLite, accessed only by the backend
using SQLAlchemy.

Suggested logical tables: - `users` --- optional for MVP; omit
authentication if time is limited. - `url_scans` --- scan ID,
user/session identifier if available, original and normalized URL,
domain, verdict, risk score, timestamp, status, model/policy version. -
`detection_results` --- scan ID, ML output, Google Safe Browsing output,
VirusTotal output, AI explanation, source status and timestamps. -
`user_decisions` --- scan ID, decision, timestamp. - `brand_domains` ---
curated official brand/domain mappings and source/version metadata, if
stored in the database rather than a versioned file.

Data protection: - Do not store passwords, cookies, authorization
headers, or browser page contents. - Redact likely tokens and sensitive
query parameters before persistence and display. - Restrict history
access to the relevant user/session. - Define a retention policy and
provide deletion capability where feasible. - Do not expose the database
directly to the browser.

### 4.9 Dashboard

The React dashboard may provide: - Scan history table. - Verdict and
risk-score filters. - Scan detail page. - Source-by-source evidence. -
SearchGuard summary. - DomainShield findings. - Aggregate scan
statistics. - User decisions for Suspicious results.

For the 24-hour MVP, prioritize scan history and scan details over
elaborate analytics.

## 5. Technology Stack and Rationale

  -----------------------------------------------------------------------
  Layer                   Technology              Reason
  ----------------------- ----------------------- -----------------------
  Browser extension       JavaScript, Chrome      Native Chrome extension
                          Manifest V3             APIs and lightweight
                                                  browser integration

  Frontend                React                   Reusable, state-driven
                                                  UI

  Build tooling           Vite                    Fast development and
                                                  builds

  Frontend language       TypeScript              Safer API contracts and
                                                  UI state

  Styling                 Tailwind CSS            Rapid, consistent UI
                                                  development

  Backend                 Python + FastAPI        Strong ML ecosystem,
                                                  async APIs, validation
                                                  and automatic OpenAPI
                                                  docs

  ASGI server             Uvicorn                 Runs FastAPI

  Validation              Pydantic                Validates requests and
                                                  structured responses

  HTTP client             HTTPX                   Async requests to
                                                  external APIs

  ML                      Existing                Reuse available model
                          PhishOFE-trained model  and avoid unnecessary
                                                  retraining

  ML libraries            Scikit-learn, XGBoost,  Preprocessing, model
                          Pandas, NumPy, Joblib   inference and
                                                  serialization as
                                                  applicable

  AI                      Anthropic Claude API    Evidence summarization
                                                  and contextual
                                                  explanation

  Threat intelligence     Google Safe Browsing    Known unsafe URL
                          API                     intelligence

  Threat intelligence     VirusTotal API v3       Multi-engine URL
                                                  reputation and analysis

  Similarity              RapidFuzz               Efficient string
                                                  similarity calculations

  Domain parsing          tldextract              Registrable domain
                                                  extraction

  IDN processing          idna                    Internationalized
                                                  domain handling

  Cache                   cachetools TTLCache     Lightweight in-process
                                                  cache

  Database                SQLite + SQLAlchemy     Persistent history
                                                  without operating a
                                                  database server

  Testing                 pytest, browser manual  Backend and end-to-end
                          tests                   validation

  Version control         Git + GitHub            Team collaboration
  -----------------------------------------------------------------------

### 5.1 Why not add Redis, Kubernetes, or microservices?

They add operational overhead without being necessary for the 24-hour
prototype. Start with one modular FastAPI application and an in-memory
cache. Consider Redis, PostgreSQL, and distributed services only when
scale or deployment requirements justify them.

## 6. High-Level User Workflows

### 6.1 Single URL navigation workflow

1.  User clicks an eligible link in a supported browser context.
2.  Extension intercepts the click and prevents default navigation.
3.  Extension opens an extension-controlled interstitial or analysis
    view.
4.  Extension submits the URL to `POST /api/v1/analyze`.
5.  Backend validates and normalizes the URL.
6.  Backend checks the cache.
7.  On a cache miss, the backend starts ML, Google Safe Browsing, and
    VirusTotal checks concurrently where possible.
8.  Backend normalizes and stores source results.
9.  Backend sends structured evidence to Claude when available.
10. Deterministic policy engine validates evidence and produces a
    verdict.
11. Backend persists the scan and evidence.
12. Backend returns the verdict and recommended action.
13. Extension applies the action:
    -   Safe: allow the original destination.
    -   Critical: keep the destination blocked.
    -   Suspicious: show warning and offer explicit proceed or cancel.
    -   Insufficient Evidence: do not label Safe; show an
        inability-to-verify warning and follow configured fail-safe
        policy.
14. If the user proceeds from Suspicious, record the decision.

### 6.2 SearchGuard workflow

1.  User loads a supported search results page.
2.  Content script identifies eligible result containers.
3.  Script extracts and normalizes destination URLs.
4.  Script deduplicates URLs and checks locally available result state.
5.  Script submits a batch to `POST /api/v1/analyze/batch`.
6.  Backend returns cached results and queues or performs remaining
    checks with bounded concurrency.
7.  Content script attaches a badge to each corresponding result.
8.  MutationObserver detects newly loaded results and repeats the
    process only for new URLs.
9.  Clicking a result still passes through the navigation protection
    flow where supported; a search badge is not a substitute for a fresh
    navigation policy check.

### 6.3 DomainShield workflow

1.  URL enters the analysis engine.
2.  Backend extracts and normalizes the hostname and registrable domain.
3.  DomainShield compares it against curated official brand domains.
4.  It checks character substitutions, edit distance, homoglyphs, and
    domain structure.
5.  It returns possible matches and evidence.
6.  Risk/policy engine combines this with ML and threat-intelligence
    signals.
7.  If a reliable official-domain mapping exists, the UI may suggest the
    official domain.
8.  User is not silently redirected to the suggested domain.

### 6.4 History workflow

1.  Each completed scan receives a unique scan ID.
2.  Backend stores scan metadata and detector evidence.
3.  Dashboard requests history from the backend.
4.  User filters or opens a scan.
5.  Backend returns only authorized records.
6.  User can inspect the analysis and, where implemented, delete
    history.

## 7. Functional Requirements

  -----------------------------------------------------------------------
  ID                      Requirement             Priority
  ----------------------- ----------------------- -----------------------
  FR-001                  The extension shall     Must
                          intercept eligible      
                          supported link-click    
                          navigation before the   
                          destination page is     
                          loaded.                 

  FR-002                  The extension shall     Must
                          submit the destination  
                          URL to the AEGIS        
                          backend.                

  FR-003                  The backend shall       Must
                          validate and normalize  
                          submitted URLs.         

  FR-004                  The engine shall obtain Must
                          an ML prediction using  
                          the configured trained  
                          model.                  

  FR-005                  The engine shall query  Must
                          Google Safe Browsing.   

  FR-006                  The engine shall query  Must
                          VirusTotal and handle   
                          asynchronous analysis.  

  FR-007                  The engine shall        Should
                          execute independent     
                          checks concurrently     
                          where feasible.         

  FR-008                  The AI layer shall      Must
                          summarize structured    
                          evidence and return a   
                          validated               
                          recommendation.         

  FR-009                  A deterministic policy  Must
                          engine shall produce    
                          the enforced verdict    
                          and action.             

  FR-010                  The system shall        Must
                          support Safe,           
                          Suspicious, and         
                          Critical user-facing    
                          verdicts.               

  FR-011                  The system shall        Must
                          internally represent    
                          insufficient evidence   
                          and service failures.   

  FR-012                  Critical destinations   Must
                          shall remain blocked in 
                          supported navigation    
                          flows.                  

  FR-013                  Suspicious destinations Must
                          shall require an        
                          explicit user decision  
                          to proceed.             

  FR-014                  Safe destinations shall Must
                          be allowed only after   
                          the configured checks   
                          and policy requirements 
                          pass.                   

  FR-015                  The system shall cache  Must
                          completed analysis      
                          results with expiry.    

  FR-016                  The system shall        Should
                          persist scan history    
                          and detection evidence. 

  FR-017                  The dashboard shall     Should
                          display scan history    
                          and scan details.       

  FR-018                  SearchGuard shall       Should
                          identify eligible       
                          results on supported    
                          search pages.           

  FR-019                  SearchGuard shall       Should
                          submit unique URLs in   
                          batches and add status  
                          badges.                 

  FR-020                  SearchGuard shall       Should
                          detect dynamically      
                          loaded result elements. 

  FR-021                  DomainShield shall      Should
                          identify possible       
                          lookalike domains.      

  FR-022                  DomainShield shall      Should
                          suggest a trusted       
                          official domain when    
                          available.              

  FR-023                  The system shall record Should
                          the user's decision for 
                          Suspicious URLs.        

  FR-024                  The system shall        Must
                          protect API keys and    
                          secrets from browser    
                          exposure.               

  FR-025                  The system shall record Must
                          source errors and avoid 
                          treating failures as    
                          safe results.           
  -----------------------------------------------------------------------

## 8. Non-Functional Requirements

### 8.1 Performance

-   The extension should show an immediate loading/interstitial state.
-   Independent detection services should run concurrently where
    possible.
-   SearchGuard should use batching, deduplication, caching, and bounded
    concurrency.
-   The prototype should target a useful end-to-end verdict within a few
    seconds under normal API conditions, but external API latency is not
    guaranteed.
-   Timeouts must be configured for every external request.

### 8.2 Security

-   All external API keys must be stored in backend environment
    variables.
-   Browser-to-backend communication must use HTTPS outside local
    development.
-   Backend must validate input and restrict accepted URL schemes to
    HTTP and HTTPS.
-   Backend must defend against SSRF if it performs any URL fetching or
    redirects inspection.
-   Do not fetch arbitrary URL content from the backend unless
    explicitly required and safely isolated.
-   Do not expose sensitive scan evidence to unauthorized users.
-   Do not permit an LLM response to override mandatory security policy.
-   Treat all webpage and URL-derived content as untrusted.

### 8.3 Reliability

-   External API failures must be represented as unavailable/error
    states.
-   One failed detector must not crash the entire scan.
-   If required evidence is unavailable, do not return Safe by default.
-   The extension must handle backend timeout, malformed response, and
    lost connectivity.
-   The system must avoid duplicate scans caused by repeated DOM
    mutations.

### 8.4 Usability and accessibility

-   Verdicts must use text and icons, not color alone.
-   Warning messages must explain the reason and available actions.
-   The Suspicious proceed action must be explicit and deliberate.
-   Critical warnings must not offer a casual one-click bypass in the
    MVP.
-   Search result badges must not obscure or break the search page.

### 8.5 Maintainability

-   Detection providers, AI analysis, policy, cache, and persistence
    must be separate modules.
-   API request/response schemas must be versioned.
-   Model and policy versions should be recorded with each scan.
-   Logs must avoid secrets and unnecessary personal information.

## 9. API Requirements

Base path: `/api/v1`

### 9.1 Analyze one URL

`POST /api/v1/analyze`

Request:

``` json
{
  "url": "https://example.com",
  "source": "chrome_extension"
}
```

Response example:

``` json
{
  "scan_id": "uuid",
  "status": "completed",
  "verdict": "SUSPICIOUS",
  "risk_score": 67,
  "action": "WARN",
  "reason": "The available signals are inconclusive.",
  "checks": {
    "ml": {"status": "completed", "prediction": "phishing"},
    "google_safe_browsing": {"status": "completed", "threat_detected": false},
    "virustotal": {"status": "completed", "malicious": 1, "suspicious": 2}
  },
  "domain_impersonation": {
    "possible_match": "example-brand",
    "official_domain": null,
    "similarity": 0.0
  }
}
```

The example values are illustrative. Production responses must reflect
actual provider data and calibrated model output.

### 9.2 Batch analysis

`POST /api/v1/analyze/batch`

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

Response should include a result keyed by normalized URL or a stable
per-item identifier, with each result carrying its own status and
verdict.

### 9.3 Scan status and details

-   `GET /api/v1/status/{scan_id}`
-   `GET /api/v1/verdict/{scan_id}`
-   `GET /api/v1/history`
-   `GET /api/v1/history/{scan_id}`
-   `DELETE /api/v1/history/{scan_id}` (if user/session authorization is
    implemented)
-   `GET /api/v1/health`

### 9.4 API response rules

-   Use explicit status fields: `pending`, `completed`, `partial`,
    `failed`.
-   Use explicit provider status: `completed`, `no_match`,
    `unavailable`, `timeout`, `error`.
-   Never encode provider failure as a negative threat match.
-   Validate all response enums using Pydantic.
-   Do not trust client-supplied verdicts or risk scores.

## 10. Data and Model Requirements

### 10.1 Dataset strategy

-   Use PhishOFE as the primary training dataset if its feature schema
    and labels are suitable for the intended URL-only model.
-   Retain the existing trained model if already available and
    validated.
-   PhishTank can provide additional verified phishing URL samples and
    temporal evaluation data, but it needs preprocessing and a separate
    legitimate URL source for balanced supervised training.
-   Keep training, validation, and test splits separate.
-   Remove duplicates and assess domain overlap to reduce leakage.
-   Prefer a temporal holdout test to measure performance on newer URLs.
-   Record dataset version, collection date, preprocessing version, and
    model version.

### 10.2 Model inference

-   The inference feature extractor must match training exactly.
-   Validate feature count, names, order, types, and missing-value
    behavior.
-   Return prediction and confidence only if supported by the model.
-   Evaluate precision, recall, F1, PR-AUC, confusion matrix, and
    false-positive rate.
-   Pay particular attention to phishing recall without allowing an
    unacceptable false-positive rate.
-   Do not claim model accuracy based only on training data.

## 11. Acceptance Criteria

The MVP is acceptable for demonstration when:

1.  An eligible link click is intercepted in the supported Chrome test
    scenario.
2.  The destination page does not load while analysis is pending.
3.  The backend receives and validates the URL.
4.  All three configured detection mechanisms return structured results
    or explicit failure states.
5.  Claude output is parsed and validated, or the system gracefully
    operates without it.
6.  The policy engine returns a supported verdict and action.
7.  Safe, Suspicious, Critical, and Insufficient Evidence flows behave
    as specified.
8.  Critical URLs remain blocked in the supported flow.
9.  Suspicious URLs require an explicit proceed/cancel decision.
10. Repeated analysis can use the cache and cache expiry works.
11. Completed scans are stored and visible in history if persistence is
    included.
12. SearchGuard annotates eligible Google results without duplicate
    badges or excessive requests.
13. DomainShield flags test lookalike domains and explains that
    similarity is not proof.
14. A verified official domain is suggested only when present in the
    trusted mapping.
15. API keys do not appear in extension files, frontend bundles, or
    browser network responses.
16. External API failures never result in an automatic Safe verdict.

## 12. 24-Hour MVP Prioritization

**P0 --- Essential** - FastAPI service and stable API schema. - Existing
ML model inference. - Google Safe Browsing integration. - VirusTotal
integration. - Deterministic risk/policy engine. - Claude evidence
explanation. - Chrome extension supported navigation flow. - Safe,
Suspicious, Critical and insufficient-evidence handling.

**P1 --- High value** - TTL cache. - SQLite scan history. - SearchGuard
for Google results. - DomainShield basic similarity detection and
curated brand mapping.

**P2 --- If time permits** - Dashboard analytics. - Rich scan detail
reports. - More search engines. - User accounts and cross-device
history. - Advanced webpage inspection.

If time becomes constrained, preserve core navigation protection and
correct fail-safe behavior before polishing secondary features.

## 13. Team and Delivery Plan

Suggested division for four members: - Member 1: FastAPI orchestration,
provider integrations, policy engine, persistence. - Member 2: Chrome
extension, navigation flow, SearchGuard DOM integration. - Member 3:
React dashboard, interstitial UI, search badges and result details. -
Member 4: ML model integration, DomainShield, integration testing and
demo scenarios.

All members should agree on API schemas and verdict enums before
parallel implementation.

## 14. Risks and Mitigations

  -----------------------------------------------------------------------
  Risk                    Impact                  Mitigation
  ----------------------- ----------------------- -----------------------
  API rate limits         Delayed or incomplete   Cache, batch, bounded
                          scans                   concurrency, graceful
                                                  unavailable state

  Provider outage         Incomplete evidence     Explicit
                                                  insufficient-evidence
                                                  behavior

  LLM hallucination       Incorrect verdict       Deterministic policy
                          explanation             and schema validation

  False positives         Legitimate sites        Calibrated thresholds,
                          blocked                 evidence-based rules,
                                                  test corpus

  False negatives         Phishing site allowed   Multiple signals,
                                                  conservative handling
                                                  of uncertainty,
                                                  continuous evaluation

  Extension coverage gaps Some navigation         Clearly define
                          bypasses checks         supported flows and
                                                  test
                                                  redirects/address-bar
                                                  cases

  Search DOM changes      SearchGuard stops       Defensive selectors,
                          working                 MutationObserver,
                                                  graceful disable

  Brand similarity false  Incorrect brand         Curated mapping,
  positives               suggestions             multiple signals, no
                                                  automatic redirect

  Sensitive URL data      Privacy exposure        Redaction, access
                                                  control, retention
                                                  limits

  SSRF                    Backend infrastructure  Avoid arbitrary
                          exposure                fetching; strict egress
                                                  and redirect/IP
                                                  validation if fetching
                                                  is added
  -----------------------------------------------------------------------

## 15. Future Roadmap

-   Firefox and other browser support.
-   More search engines.
-   Domain age, DNS, certificate, and passive DNS signals.
-   Safer webpage inspection using an isolated sandbox.
-   User accounts and synchronized history.
-   Organization-level policies and reporting.
-   Feedback loop for false positives and false negatives.
-   Model retraining and drift monitoring.
-   Threat-intelligence feed enrichment.
-   Browser-level policy enforcement for more navigation paths.

## 16. Glossary

-   **AEGIS:** AI-Powered Phishing Detection and Browser Protection
    System.
-   **URL:** Uniform Resource Locator.
-   **ML:** Machine Learning.
-   **LLM:** Large Language Model.
-   **SERP:** Search Engine Results Page.
-   **SSRF:** Server-Side Request Forgery.
-   **TTL:** Time to Live.
-   **IDN:** Internationalized Domain Name.
-   **Typosquatting:** Registering or using a domain that resembles
    another domain, often to deceive users.
-   **Homoglyph:** A character that looks similar to another character.
-   **Verdict:** User-facing security classification.
