import type { NavigationState, VerificationRecord, Verdict } from '../types/extension';

// In-memory cache for ultra-fast synchronous lookup in onBeforeNavigate
const recordsByNavId = new Map<string, VerificationRecord>();
const activeRedirectsByTab = new Map<number, { url: string; timestamp: number }>();

// Frontend & Backend endpoints to exclude from interception
export const DEFAULT_FRONTEND_URL = 'http://127.0.0.1:3000';
export const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8000';

export function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.replace(/\/+$/, '') || '/';
    return `${parsed.protocol}//${hostname}${pathname}${parsed.search}`;
  } catch {
    return url.trim().toLowerCase();
  }
}

/**
 * Detects whether a URL is a legitimate search engine or keyword search query.
 * Browser keyword searches and search engine pages are safe user queries and
 * MUST NEVER be intercepted, redirected, or blocked by Aegis.
 */
export function isSearchEngineUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false;

  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();

    // 1. Google Search & regional domains (google.com, google.co.in, google.co.uk, etc.)
    if (
      host === 'google.com' ||
      host.endsWith('.google.com') ||
      host.includes('google.')
    ) {
      return true;
    }

    // 2. Microsoft Bing (bing.com, www.bing.com, cn.bing.com)
    if (host === 'bing.com' || host.endsWith('.bing.com')) {
      return true;
    }

    // 3. DuckDuckGo (duckduckgo.com)
    if (host === 'duckduckgo.com' || host.endsWith('.duckduckgo.com')) {
      return true;
    }

    // 4. Yahoo Search (search.yahoo.com, yahoo.com)
    if (
      host === 'yahoo.com' ||
      host.endsWith('.yahoo.com') ||
      host === 'search.yahoo.com' ||
      host.endsWith('.search.yahoo.com')
    ) {
      return true;
    }

    // 5. Brave Search (search.brave.com, brave.com)
    if (host === 'search.brave.com' || host.endsWith('.brave.com')) {
      return true;
    }

    // 6. Ecosia (ecosia.org)
    if (host === 'ecosia.org' || host.endsWith('.ecosia.org')) {
      return true;
    }

    // 7. Startpage (startpage.com)
    if (host === 'startpage.com' || host.endsWith('.startpage.com')) {
      return true;
    }

    // 8. Kagi (kagi.com)
    if (host === 'kagi.com' || host.endsWith('.kagi.com')) {
      return true;
    }

    // 9. Yandex (yandex.com, yandex.ru, ya.ru)
    if (
      host === 'yandex.com' ||
      host.endsWith('.yandex.com') ||
      host === 'yandex.ru' ||
      host.endsWith('.yandex.ru') ||
      host === 'ya.ru'
    ) {
      return true;
    }

    // 10. Baidu (baidu.com)
    if (host === 'baidu.com' || host.endsWith('.baidu.com')) {
      return true;
    }

    // 11. Ask.com
    if (host === 'ask.com' || host.endsWith('.ask.com')) {
      return true;
    }

    // 12. WolframAlpha & Qwant
    if (
      host === 'wolframalpha.com' ||
      host.endsWith('.wolframalpha.com') ||
      host === 'qwant.com' ||
      host.endsWith('.qwant.com')
    ) {
      return true;
    }

    // 13. Generic search path with search query parameters (e.g. /search?q=..., /results?q=...)
    const hasSearchParam =
      parsed.searchParams.has('q') ||
      parsed.searchParams.has('query') ||
      parsed.searchParams.has('p') ||
      parsed.searchParams.has('wd') ||
      parsed.searchParams.has('text');

    if (
      (path.includes('/search') || path.includes('/results') || path.includes('/web')) &&
      hasSearchParam
    ) {
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

/**
 * Checks whether a URL is exempt from security gateway interception.
 * Exclusions include browser internals, AEGIS frontend/backend, and search engine queries.
 */
export function isExcludedFromInterception(url: string): boolean {
  if (!url || typeof url !== 'string') return true;

  const trimmed = url.trim().toLowerCase();

  // 1. Internal browser schemes
  if (
    trimmed.startsWith('chrome://') ||
    trimmed.startsWith('chrome-extension://') ||
    trimmed.startsWith('edge://') ||
    trimmed.startsWith('about:') ||
    trimmed.startsWith('devtools://') ||
    trimmed.startsWith('view-source:') ||
    trimmed.startsWith('data:') ||
    trimmed.startsWith('blob:') ||
    trimmed.startsWith('javascript:') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('mailto:')
  ) {
    return true;
  }

  // 2. Only intercept HTTP and HTTPS
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    return true;
  }

  // 3. Search Engine Queries & Keywords in browser are completely exempt from interception
  if (isSearchEngineUrl(url)) {
    return true;
  }

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const port = parsed.port;

    // 4. Narrowly scoped AEGIS Frontend & Backend infrastructure
    const isLocal =
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname === '::1';

    if (isLocal) {
      // Exclude only the specific ports used by AEGIS frontend (3000, 5173) and backend (8000)
      if (port === '3000' || port === '5173' || port === '8000') {
        return true;
      }
      // If no port specified and host is localhost, check default app ports
      if (!port) {
        return false;
      }
    }
  } catch {
    return true;
  }

  return false;
}

/**
 * Synchronizes records to chrome.storage.session so state survives service worker restarts.
 */
async function persistState(): Promise<void> {
  try {
    if (chrome.storage && chrome.storage.session) {
      const recordsArray = Array.from(recordsByNavId.values());
      await chrome.storage.session.set({ aegis_nav_records: recordsArray });
    }
  } catch (err) {
    console.warn('[AEGIS State] Failed to persist records to storage.session:', err);
  }
}

/**
 * Restores state from chrome.storage.session upon service worker wake-up.
 */
export async function initNavigationStore(): Promise<void> {
  try {
    if (chrome.storage && chrome.storage.session) {
      const data = await chrome.storage.session.get('aegis_nav_records');
      const records = data?.aegis_nav_records as VerificationRecord[] | undefined;
      if (Array.isArray(records)) {
        const now = Date.now();
        for (const r of records) {
          if (r.expiresAt > now) {
            recordsByNavId.set(r.navId, r);
          }
        }
      }
    }
  } catch (err) {
    console.warn('[AEGIS State] Failed to restore records from storage.session:', err);
  }
}

/**
 * Creates a unique pending verification record for an unverified navigation.
 */
export function createPendingNavigation(tabId: number, originalUrl: string): VerificationRecord {
  const navId = `nav_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  const normalized = normalizeUrl(originalUrl);
  let destinationHost = '';
  try {
    destinationHost = new URL(originalUrl).hostname.toLowerCase();
  } catch {
    destinationHost = originalUrl;
  }

  const record: VerificationRecord = {
    navId,
    tabId,
    originalUrl,
    normalizedUrl: normalized,
    destinationHost,
    state: 'PENDING',
    createdAt: Date.now(),
    expiresAt: Date.now() + 60000, // 60s TTL to complete analysis
    consumed: false,
  };

  recordsByNavId.set(navId, record);
  activeRedirectsByTab.set(tabId, { url: normalized, timestamp: Date.now() });

  // Asynchronously persist without blocking the navigation flow
  persistState();

  return record;
}

/**
 * Checks whether an incoming navigation for a specific tab has an unexpired authorization.
 */
export function findActiveAuthorizedRecord(tabId: number, targetUrl: string): VerificationRecord | null {
  const normalized = normalizeUrl(targetUrl);
  const now = Date.now();

  for (const record of recordsByNavId.values()) {
    if (
      record.tabId === tabId &&
      record.normalizedUrl === normalized &&
      record.state === 'AUTHORIZED' &&
      now <= record.expiresAt
    ) {
      return record;
    }
  }

  return null;
}

/**
 * Checks if a tab is already in the middle of being redirected for this URL.
 * Prevents recursive redirection storms if multiple events fire in milliseconds.
 */
export function isTabRedirectingForUrl(tabId: number, url: string): boolean {
  const active = activeRedirectsByTab.get(tabId);
  if (!active) return false;

  const normalized = normalizeUrl(url);
  const isRecent = Date.now() - active.timestamp < 3500; // 3.5s window
  return isRecent && active.url === normalized;
}

/**
 * Authorizes a navigation record. Strictly scoped to that destination and tab.
 */
export function authorizeNavigationRecord(
  navId: string,
  url: string,
  verdict: Verdict | 'SUSPICIOUS_PROCEED',
  tabId?: number
): { success: boolean; error?: string; record?: VerificationRecord } {
  const record = recordsByNavId.get(navId);
  if (!record) {
    return { success: false, error: `Navigation identifier '${navId}' not found or expired.` };
  }

  if (tabId && record.tabId !== tabId) {
    return { success: false, error: 'Tab context mismatch for navigation authorization.' };
  }

  const normalizedInput = normalizeUrl(url);
  if (record.normalizedUrl !== normalizedInput) {
    return { success: false, error: 'Target URL does not match original navigation destination.' };
  }

  if (verdict === 'MALICIOUS' || verdict === 'CRITICAL') {
    return { success: false, error: 'Malicious destinations cannot be authorized.' };
  }

  const now = Date.now();
  record.state = 'AUTHORIZED';
  record.authorizedAt = now;
  record.verdict = verdict === 'SUSPICIOUS_PROCEED' ? 'SUSPICIOUS' : (verdict as Verdict);
  // Authorizations are short-lived (30s for safe, 20s for suspicious user override)
  record.expiresAt = now + (verdict === 'SAFE' ? 30000 : 20000);
  record.consumed = false;

  // Clear pending redirect lock
  activeRedirectsByTab.delete(record.tabId);

  persistState();

  return { success: true, record };
}

/**
 * Updates a record's state (e.g. ANALYZING, BLOCKED, FAILED).
 */
export function updateNavigationState(navId: string, state: NavigationState): boolean {
  const record = recordsByNavId.get(navId);
  if (!record) return false;

  record.state = state;
  persistState();
  return true;
}

/**
 * Returns a record by navId.
 */
export function getNavigationRecord(navId: string): VerificationRecord | undefined {
  return recordsByNavId.get(navId);
}

/**
 * Periodically cleans up expired records to prevent memory and storage bloat.
 */
export function cleanupExpiredRecords(): void {
  const now = Date.now();
  let changed = false;

  for (const [navId, record] of recordsByNavId.entries()) {
    if (now > record.expiresAt) {
      recordsByNavId.delete(navId);
      changed = true;
    }
  }

  for (const [tabId, redirect] of activeRedirectsByTab.entries()) {
    if (now - redirect.timestamp > 10000) {
      activeRedirectsByTab.delete(tabId);
    }
  }

  if (changed) {
    persistState();
  }
}
