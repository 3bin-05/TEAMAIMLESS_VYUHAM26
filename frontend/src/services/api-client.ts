import type {
  AnalyzeRequest,
  AnalyzeResponse,
  BatchAnalyzeRequest,
  BatchAnalyzeResponse,
  HealthResponse,
  ScanHistoryItem,
  ScanHistoryResponse,
  UserDecisionRequest,
  UserDecisionResponse,
} from '../types/api';

const DEFAULT_API_BASE_URL = 'http://localhost:8000';
const STORAGE_KEY_API_BASE = 'aegis_api_base_url';

export class ApiError extends Error {
  public status?: number;
  public isNetworkError: boolean;
  public details?: unknown;

  constructor(message: string, status?: number, isNetworkError = false, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.isNetworkError = isNetworkError;
    this.details = details;
  }
}

export class ApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = this.getStoredBaseUrl();
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setBaseUrl(url: string): void {
    const trimmed = url.trim().replace(/\/+$/, '');
    this.baseUrl = trimmed || DEFAULT_API_BASE_URL;
    try {
      localStorage.setItem(STORAGE_KEY_API_BASE, this.baseUrl);
    } catch {
      // Ignore localStorage failure in restricted contexts
    }
  }

  private getStoredBaseUrl(): string {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_API_BASE);
      if (stored && stored.trim()) {
        return stored.trim().replace(/\/+$/, '');
      }
    } catch {
      // Ignore
    }
    return import.meta.env?.VITE_API_BASE_URL || DEFAULT_API_BASE_URL;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

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
        let errorData: unknown;
        try {
          errorData = await response.json();
        } catch {
          errorData = await response.text();
        }
        throw new ApiError(
          `Backend returned ${response.status}: ${response.statusText}`,
          response.status,
          false,
          errorData
        );
      }

      const data = await response.json();
      return data as T;
    } catch (err) {
      clearTimeout(timeout);
      if (err instanceof ApiError) {
        throw err;
      }
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new ApiError('Request timed out while waiting for AEGIS backend', 408, true);
      }
      const message = err instanceof Error ? err.message : 'Unknown network error';
      throw new ApiError(
        `Unable to connect to AEGIS backend at ${this.baseUrl}. Please verify the service is running. (${message})`,
        undefined,
        true
      );
    }
  }

  /**
   * Analyse a URL using POST /api/v1/analyze
   */
  public async analyzeUrl(url: string, source: 'dashboard' | 'chrome_extension' = 'dashboard'): Promise<AnalyzeResponse> {
    const payload: AnalyzeRequest = { url, source };
    return this.request<AnalyzeResponse>('/api/v1/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Batch analyze URLs using POST /api/v1/analyze/batch
   */
  public async batchAnalyze(urls: string[]): Promise<BatchAnalyzeResponse> {
    const payload: BatchAnalyzeRequest = { urls, source: 'search_guard' };
    return this.request<BatchAnalyzeResponse>('/api/v1/analyze/batch', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Check status of an ongoing scan via GET /api/v1/status/{scan_id}
   */
  public async getScanStatus(scanId: string): Promise<{ scan_id: string; status: string; progress?: number }> {
    return this.request<{ scan_id: string; status: string; progress?: number }>(`/api/v1/status/${encodeURIComponent(scanId)}`);
  }

  /**
   * Retrieve final verdict via GET /api/v1/verdict/{scan_id}
   */
  public async getVerdict(scanId: string): Promise<AnalyzeResponse> {
    return this.request<AnalyzeResponse>(`/api/v1/verdict/${encodeURIComponent(scanId)}`);
  }

  /**
   * List authorized scan history via GET /api/v1/history
   */
  public async getHistory(): Promise<ScanHistoryItem[]> {
    const res = await this.request<ScanHistoryResponse | ScanHistoryItem[]>('/api/v1/history');
    if (Array.isArray(res)) {
      return res;
    }
    if (res && Array.isArray(res.scans)) {
      return res.scans;
    }
    return [];
  }

  /**
   * Retrieve specific scan details via GET /api/v1/history/{scan_id}
   */
  public async getHistoryScan(scanId: string): Promise<AnalyzeResponse> {
    return this.request<AnalyzeResponse>(`/api/v1/history/${encodeURIComponent(scanId)}`);
  }

  /**
   * Record user decision on suspicious verdict via POST /api/v1/decisions
   */
  public async recordDecision(request: UserDecisionRequest): Promise<UserDecisionResponse> {
    return this.request<UserDecisionResponse>('/api/v1/decisions', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Backend health check via GET /api/v1/health
   */
  public async checkHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/v1/health');
  }
}

export const apiClient = new ApiClient();
