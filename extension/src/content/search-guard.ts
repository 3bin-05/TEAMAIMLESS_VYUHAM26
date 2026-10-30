import type { BatchAnalyzeResponse, BatchItemResult, Verdict } from '../types/extension';

// Set of URLs currently being processed or already badge-attached
const processedUrls = new Set<string>();
const pendingBatch = new Map<string, HTMLElement[]>();
let batchDebounceTimer: number | null = null;

function normalizeUrl(rawUrl: string): string {
  try {
    let url = rawUrl;
    // Extract actual URL if wrapped in Google redirect (/url?q=... or /url?url=...)
    if (url.includes('/url?')) {
      const parsed = new URL(url);
      const q = parsed.searchParams.get('q') || parsed.searchParams.get('url');
      if (q) url = q;
    }
    const target = new URL(url);
    if (target.protocol !== 'http:' && target.protocol !== 'https:') return '';
    // Skip google internal links and subdomains
    if (target.hostname.endsWith('google.com') || target.hostname.endsWith('google.co.in') || target.hostname.includes('google.')) {
      return '';
    }
    return `${target.protocol}//${target.hostname.toLowerCase()}${target.pathname.replace(/\/+$/, '') || '/'}${target.search}`;
  } catch {
    return '';
  }
}

function createBadge(verdict: Verdict | 'CHECKING', reason?: string): HTMLElement {
  const badge = document.createElement('span');
  badge.className = 'aegis-search-badge';
  badge.setAttribute('role', 'status');
  badge.setAttribute('aria-label', `AEGIS Security: ${verdict}`);

  const baseStyle = `
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 7px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 700;
    line-height: 1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    vertical-align: middle;
    margin-left: 8px;
    letter-spacing: 0.02em;
    user-select: none;
    box-sizing: border-box;
  `;

  if (verdict === 'CHECKING') {
    badge.style.cssText = `${baseStyle} background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE;`;
    badge.innerHTML = `
      <span style="display:inline-block; width:10px; height:10px; border:2px solid #2563EB; border-top-color:transparent; border-radius:50%; animation: aegisSpin 0.8s linear infinite;"></span>
      <span>Checking</span>
    `;
  } else if (verdict === 'SAFE') {
    badge.style.cssText = `${baseStyle} background: #ECFDF5; color: #047857; border: 1px solid #A7F3D0;`;
    badge.innerHTML = `
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM14.707 7.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l5-5z" clip-rule="evenodd"/></svg>
      <span>Safe</span>
    `;
    if (reason) badge.title = `AEGIS: ${reason}`;
  } else if (verdict === 'SUSPICIOUS') {
    badge.style.cssText = `${baseStyle} background: #FFFBEB; color: #B45309; border: 1px solid #FDE68A;`;
    badge.innerHTML = `
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
      <span>Suspicious</span>
    `;
    if (reason) badge.title = `AEGIS Warning: ${reason}`;
  } else if (verdict === 'CRITICAL') {
    badge.style.cssText = `${baseStyle} background: #FEF2F2; color: #B91C1C; border: 1px solid #FECACA;`;
    badge.innerHTML = `
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"/></svg>
      <span>Critical Threat</span>
    `;
    if (reason) badge.title = `AEGIS Critical: ${reason}`;
  } else {
    badge.style.cssText = `${baseStyle} background: #F1F5F9; color: #475569; border: 1px solid #CBD5E1;`;
    badge.innerHTML = `<span>Unable to Verify</span>`;
  }

  return badge;
}

function processBatch() {
  if (pendingBatch.size === 0) return;

  const currentBatch = new Map(pendingBatch);
  pendingBatch.clear();

  const urlsToAnalyze = Array.from(currentBatch.keys());

  chrome.runtime.sendMessage(
    {
      type: 'BATCH_ANALYZE',
      payload: urlsToAnalyze,
    },
    (res) => {
      const responseData = res?.data as unknown as { results?: unknown } | undefined;
      const resultsRaw = responseData?.results;
      const results: Record<string, BatchItemResult> = {};
      if (Array.isArray(resultsRaw)) {
        resultsRaw.forEach((item: { url?: string; verdict?: Verdict; reason?: string }) => {
          if (item?.url) {
            results[item.url] = item as BatchItemResult;
          }
        });
      } else if (resultsRaw && typeof resultsRaw === 'object') {
        Object.assign(results, resultsRaw);
      }

      for (const [url, elements] of currentBatch.entries()) {
        const itemResult = results[url];
        const verdict: Verdict = itemResult ? itemResult.verdict : 'INSUFFICIENT_EVIDENCE';
        const reason: string | undefined = itemResult?.reason;

        elements.forEach((el) => {
          // Remove checking badge
          const existingChecking = el.querySelector('.aegis-search-badge');
          if (existingChecking) existingChecking.remove();

          // Attach final verdict badge
          const finalBadge = createBadge(verdict, reason);
          el.appendChild(finalBadge);
        });
      }
    }
  );
}

function scanSearchResults() {
  // Common organic search result containers on Google
  // e.g. div.g, div[data-sokoban-container], div.yuRUbf > a
  const anchors = document.querySelectorAll<HTMLAnchorElement>(
    '#search a[href], #rso a[href], div.g a[href]'
  );

  anchors.forEach((anchor) => {
    // Check if this anchor is the primary result title (has an h3 inside)
    const h3 = anchor.querySelector('h3');
    if (!h3) return;

    // Check if already processed
    if (anchor.dataset.aegisScanned === 'true') return;
    anchor.dataset.aegisScanned = 'true';

    const normalized = normalizeUrl(anchor.href);
    if (!normalized) return;

    // Attach initial 'Checking' badge immediately
    const checkingBadge = createBadge('CHECKING');
    h3.appendChild(checkingBadge);

    // Queue for batch
    if (!pendingBatch.has(normalized)) {
      pendingBatch.set(normalized, []);
    }
    pendingBatch.get(normalized)!.push(h3);
  });

  // Debounce batch processing by 150ms
  if (batchDebounceTimer !== null) {
    window.clearTimeout(batchDebounceTimer);
  }
  batchDebounceTimer = window.setTimeout(processBatch, 150);
}

// Initial scan
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanSearchResults);
} else {
  scanSearchResults();
}

// MutationObserver to watch for dynamic infinite-scroll additions
const observer = new MutationObserver(() => {
  scanSearchResults();
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

console.log('[AEGIS SearchGuard] Monitoring organic Google search results.');
