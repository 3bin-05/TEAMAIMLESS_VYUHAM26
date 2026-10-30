/**
 * AEGIS Navigation Guard (Content Script)
 * Runs at document_start to enforce fail-closed security and provide
 * a seamless communication bridge between the AEGIS Frontend and Extension Service Worker.
 */

// 1. Identify if current page is the AEGIS Frontend
const currentUrl = window.location.href;
const isLocalhostFrontend =
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
  (window.location.port === '3000' || window.location.port === '5173');

if (isLocalhostFrontend) {
  // Mark DOM so the AEGIS web app knows the extension is installed and active
  document.documentElement.setAttribute('data-aegis-extension-active', 'true');
  document.documentElement.setAttribute('data-aegis-version', '1.0.0');

  // Frontend-to-Extension Messaging Bridge
  window.addEventListener('message', (event) => {
    // Only accept messages from the trusted frontend window
    if (event.source !== window || !event.data || event.data.source !== 'AEGIS_FRONTEND') {
      return;
    }

    const { requestId, type, payload } = event.data;

    chrome.runtime.sendMessage({ type, payload }, (response) => {
      window.postMessage(
        {
          source: 'AEGIS_EXTENSION',
          requestId,
          response,
        },
        '*'
      );
    });
  });

  console.log('[AEGIS Content Script] Frontend Communication Bridge active on localhost:3000.');
} else {
  // 2. Active Tab Protection for External Destinations
  // Check if current top-level navigation has been authorized
  if (window === window.top) {
    const isExcluded =
      currentUrl.startsWith('chrome') ||
      currentUrl.startsWith('about:') ||
      currentUrl.startsWith('data:') ||
      currentUrl.startsWith('blob:');

    if (!isExcluded) {
      chrome.runtime.sendMessage(
        {
          type: 'CHECK_APPROVAL',
          payload: { url: currentUrl },
        },
        (res) => {
          if (chrome.runtime.lastError) {
            return;
          }

          // If background has not authorized this page load, fail closed
          if (res && res.approved === false) {
            console.warn('[AEGIS Guard] Unauthorized destination load detected. Halting page.');
            window.stop();
            // Hand off to service worker or redirect
            chrome.runtime.sendMessage({
              type: 'ANALYZE_URL',
              payload: { url: currentUrl, source: 'chrome_extension' },
            });
          }
        }
      );
    }
  }

  // 3. Link Click Interception Helper
  document.addEventListener(
    'click',
    (event: MouseEvent) => {
      // Let special clicks (Ctrl, Cmd, middle click) pass to onBeforeNavigate
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey) {
        return;
      }

      let curr: HTMLElement | null = event.target as HTMLElement;
      while (curr && curr !== document.body) {
        if (curr instanceof HTMLAnchorElement && curr.href) {
          const href = curr.href.trim();
          if (
            (href.startsWith('http://') || href.startsWith('https://')) &&
            !href.startsWith(window.location.href + '#') &&
            !curr.hasAttribute('download')
          ) {
            // Service worker's onBeforeNavigate will intercept and evaluate this navigation.
            return;
          }
        }
        curr = curr.parentElement;
      }
    },
    true
  );
}
