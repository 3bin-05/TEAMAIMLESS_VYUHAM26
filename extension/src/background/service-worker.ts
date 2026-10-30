import { extensionApiClient } from '../services/api-client';
import type {
  AnalyzeResponse,
  AnalyzeUrlPayload,
  AuthorizeNavigationPayload,
  CheckApprovalPayload,
  ExtensionMessage,
  RecordDecisionPayload,
} from '../types/extension';
import {
  DEFAULT_FRONTEND_URL,
  authorizeNavigationRecord,
  cleanupExpiredRecords,
  createPendingNavigation,
  findActiveAuthorizedRecord,
  getNavigationRecord,
  initNavigationStore,
  isExcludedFromInterception,
  isTabRedirectingForUrl,
  updateNavigationState,
} from './navigation-state';

// Initialize navigation storage on service worker start
initNavigationStore();

/**
 * Retrieves configured frontend base URL.
 */
async function getFrontendBaseUrl(): Promise<string> {
  try {
    const data = await chrome.storage.local.get(['frontendUrl']);
    if (data?.frontendUrl && typeof data.frontendUrl === 'string') {
      return data.frontendUrl.replace(/\/+$/, '');
    }
  } catch (err) {
    console.warn('[AEGIS Gateway] Could not read frontendUrl from storage:', err);
  }
  return DEFAULT_FRONTEND_URL;
}

/**
 * PRIMARY NAVIGATION INTERCEPTOR (Phase 3)
 * Intercepts top-level HTTP/HTTPS navigation initiated via:
 * - Address bar (omnibox)
 * - Hyperlink clicks
 * - New tabs & new windows
 * - Browser refresh
 * - JavaScript navigation (location.href)
 * - Form submissions
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept top-level main frame navigations
  if (details.frameId !== 0) {
    return;
  }

  const targetUrl = details.url;
  const tabId = details.tabId;

  // 1. Exclude internal browser pages and AEGIS frontend/backend
  if (isExcludedFromInterception(targetUrl)) {
    return;
  }

  // 2. Check if this exact navigation has an active authorization (Loop Prevention - Phase 5)
  const authorizedRecord = findActiveAuthorizedRecord(tabId, targetUrl);
  if (authorizedRecord) {
    console.log(`[AEGIS Gateway] Navigation AUTHORIZED for tab ${tabId} -> ${targetUrl}. Allowing without redirect.`);
    return;
  }

  // 3. Prevent duplicate redirects if tab is already mid-redirect to AEGIS for this URL
  if (isTabRedirectingForUrl(tabId, targetUrl)) {
    console.log(`[AEGIS Gateway] Tab ${tabId} already redirecting for ${targetUrl}. Debouncing duplicate event.`);
    return;
  }

  // 4. Create unique verification record and redirect to AEGIS Frontend
  const record = createPendingNavigation(tabId, targetUrl);
  const frontendBase = await getFrontendBaseUrl();
  const redirectUrl = `${frontendBase}/analyze?url=${encodeURIComponent(targetUrl)}&nav_id=${record.navId}&tab_id=${tabId}`;

  console.log(`[AEGIS Gateway] Intercepting tab ${tabId} -> ${targetUrl}. Redirecting to AEGIS: ${redirectUrl}`);

  try {
    await chrome.tabs.update(tabId, { url: redirectUrl });
  } catch (err) {
    console.error(`[AEGIS Gateway] Failed to redirect tab ${tabId}:`, err);
  }
});

/**
 * Handle incoming messages from content scripts and extension components.
 */
chrome.runtime.onMessage.addListener((message: ExtensionMessage, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? 0;
  handleMessage(message, tabId, sendResponse);
  return true; // Keep channel open for async responses
});

/**
 * Handle external messages from legitimate AEGIS frontend pages (Phase 7).
 */
chrome.runtime.onMessageExternal.addListener((message: ExtensionMessage, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? 0;
  console.log(`[AEGIS Gateway] External message from ${sender.url || sender.origin}:`, message.type);
  handleMessage(message, tabId, sendResponse);
  return true;
});

function handleMessage(
  message: ExtensionMessage,
  senderTabId: number,
  sendResponse: (res: unknown) => void
): void {
  switch (message.type) {
    case 'AUTHORIZE_NAVIGATION': {
      const payload = message.payload as AuthorizeNavigationPayload;
      const targetTabId = payload.tabId || senderTabId;

      const authResult = authorizeNavigationRecord(
        payload.navId,
        payload.url,
        payload.verdict,
        targetTabId
      );

      if (!authResult.success) {
        console.warn(`[AEGIS Gateway] Authorization rejected for nav ${payload.navId}: ${authResult.error}`);
        sendResponse({ success: false, error: authResult.error });
        return;
      }

      console.log(`[AEGIS Gateway] Navigation ${payload.navId} successfully AUTHORIZED for tab ${targetTabId}.`);

      // Resume navigation to original URL
      const record = authResult.record;
      if (record && targetTabId > 0) {
        chrome.tabs.update(targetTabId, { url: record.originalUrl }).catch((err) => {
          console.warn(`[AEGIS Gateway] Tab update failed during resume:`, err);
        });
      }

      sendResponse({ success: true, authorized: true, record });
      break;
    }

    case 'SET_NAVIGATION_STATE': {
      const payload = message.payload as { navId: string; state: any };
      const updated = updateNavigationState(payload.navId, payload.state);
      sendResponse({ success: updated });
      break;
    }

    case 'GET_NAVIGATION_STATE': {
      const payload = message.payload as { navId: string };
      const record = getNavigationRecord(payload.navId);
      sendResponse({ success: !!record, record });
      break;
    }

    case 'CHECK_APPROVAL': {
      const payload = message.payload as CheckApprovalPayload;
      const effectiveTabId = payload.tabId || senderTabId;
      const approvedRecord = findActiveAuthorizedRecord(effectiveTabId, payload.url);
      sendResponse({ approved: !!approvedRecord, record: approvedRecord });
      break;
    }

    case 'REGISTER_APPROVAL': {
      const payload = message.payload as { tabId: number; url: string; attemptId: string };
      const effectiveTabId = payload.tabId || senderTabId;
      const navId = `nav_reg_${Date.now()}`;
      const record = createPendingNavigation(effectiveTabId, payload.url);
      authorizeNavigationRecord(record.navId, payload.url, 'SAFE', effectiveTabId);
      sendResponse({ registered: true, navId: record.navId });
      break;
    }

    case 'ANALYZE_URL': {
      const payload = message.payload as AnalyzeUrlPayload;
      extensionApiClient
        .analyzeUrl(payload.url, payload.source || 'chrome_extension')
        .then((verdictResponse: AnalyzeResponse) => {
          sendResponse({ success: true, data: verdictResponse, attemptId: payload.attemptId });
        })
        .catch((error: Error) => {
          sendResponse({
            success: false,
            error: error.message || 'Analysis service unreachable',
            verdict: 'INSUFFICIENT_EVIDENCE',
            action: 'WARN',
          });
        });
      break;
    }

    case 'BATCH_ANALYZE': {
      const urls = message.payload as string[];
      extensionApiClient
        .batchAnalyze(urls)
        .then((response) => sendResponse({ success: true, data: response }))
        .catch((error: Error) => sendResponse({ success: false, error: error.message }));
      break;
    }

    case 'RECORD_DECISION': {
      const payload = message.payload as RecordDecisionPayload;
      extensionApiClient
        .recordDecision(payload)
        .then((res) => sendResponse({ success: true, data: res }))
        .catch((err: Error) => sendResponse({ success: false, error: err.message }));
      break;
    }

    case 'GET_CONFIG': {
      Promise.all([extensionApiClient.getBaseUrl(), getFrontendBaseUrl()]).then(
        ([backendUrl, frontendUrl]) => {
          sendResponse({ backendUrl, frontendUrl });
        }
      );
      break;
    }

    case 'SET_CONFIG': {
      const { backendUrl, frontendUrl } = message.payload as {
        backendUrl?: string;
        frontendUrl?: string;
      };
      const promises: Promise<unknown>[] = [];
      if (backendUrl) promises.push(extensionApiClient.setBaseUrl(backendUrl));
      if (frontendUrl) promises.push(chrome.storage.local.set({ frontendUrl }));
      Promise.all(promises).then(() => sendResponse({ success: true }));
      break;
    }

    case 'HEALTH_CHECK': {
      extensionApiClient
        .checkHealth()
        .then((data) => sendResponse({ online: true, data }))
        .catch((err: Error) => sendResponse({ online: false, error: err.message }));
      break;
    }

    default:
      sendResponse({ error: 'Unknown message type' });
      break;
  }
}

// Clean up stale approvals and expired verification records
setInterval(cleanupExpiredRecords, 15000);

console.log('[AEGIS Service Worker] Real-Time Navigation Interception & Gateway Active.');
