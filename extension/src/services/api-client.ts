import type {
  AnalyzeResponse,
  BatchAnalyzeResponse,
  RecordDecisionPayload,
} from '../types/extension';

const DEFAULT_API_BASE_URL = 'http://localhost:8000';
const STORAGE_KEY_API_BASE = 'aegis_api_base_url';

export class ExtensionApiClient {
  private cachedBaseUrl: string = DEFAULT_API_BASE_URL;

  constructor() {
    this.initBaseUrl();
  }

  private async initBaseUrl(): Promise<void> {
    try {
      const data = await chrome.storage.local.get([STORAGE_KEY_API_BASE]);
      if (data[STORAGE_KEY_API_BASE]) {
        this.cachedBaseUrl = (data[STORAGE_KEY_API_BASE] as string).trim().replace(/\/+$/, '');
      }
    } catch {
      // Fallback to default
    }
  }

  public async getBaseUrl(): Promise<string> {
    try {
      const data = await chrome.storage.local.get([STORAGE_KEY_API_BASE]);
      if (data[STORAGE_KEY_API_BASE]) {
        this.cachedBaseUrl = (data[STORAGE_KEY_API_BASE] as string).trim().replace(/\/+$/, '');
      }
    } catch {
      // Ignore
    }
    return this.cachedBaseUrl;
  }

  public async setBaseUrl(url: string): Promise<void> {
    const trimmed = url.trim().replace(/\/+$/, '') || DEFAULT_API_BASE_URL;
    this.cachedBaseUrl = trimmed;
    await chrome.storage.local.set({ [STORAGE_KEY_API_BASE]: trimmed });
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const baseUrl = await this.getBaseUrl();
    const url = `${baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(options.headers || {}),
        },
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`AEGIS backend error HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return data as T;
    } catch (err) {
      clearTimeout(timeout);
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new Error('Analysis timed out waiting for AEGIS backend');
      }
      throw err;
    }
  }

  public async analyzeUrl(url: string, source: 'chrome_extension' | 'search_guard' | 'dashboard' = 'chrome_extension'): Promise<AnalyzeResponse> {
    return this.request<AnalyzeResponse>('/api/v1/analyze', {
      method: 'POST',
      body: JSON.stringify({ url, source }),
    });
  }

  public async batchAnalyze(urls: string[]): Promise<BatchAnalyzeResponse> {
    return this.request<BatchAnalyzeResponse>('/api/v1/analyze/batch', {
      method: 'POST',
      body: JSON.stringify({ urls, source: 'search_guard' }),
    });
  }

  public async recordDecision(payload: RecordDecisionPayload): Promise<{ status: string }> {
    return this.request<{ status: string }>('/api/v1/decisions', {
      method: 'POST',
      body: JSON.stringify({
        scan_id: payload.scan_id,
        url: payload.url,
        decision: payload.decision,
        timestamp: new Date().toISOString(),
      }),
    });
  }

  public async checkHealth(): Promise<{ status: string }> {
    return this.request<{ status: string }>('/api/v1/health');
  }
}

export const extensionApiClient = new ExtensionApiClient();
