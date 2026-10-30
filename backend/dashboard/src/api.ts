import type {
  HealthResponse,
  AIStatusResponse,
  AnalyzeResponse,
  ScanHistoryItem,
  ScanDetailResponse,
} from './types';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

export async function fetchHealth(): Promise<HealthResponse> {
  const resp = await fetch(`${API_BASE}/health`);
  if (!resp.ok) throw new Error(`Health check failed: ${resp.status}`);
  return resp.json();
}

export async function fetchAIStatus(): Promise<AIStatusResponse> {
  const resp = await fetch(`${API_BASE}/ai/status`);
  if (!resp.ok) throw new Error(`AI status inquiry failed: ${resp.status}`);
  return resp.json();
}

export async function analyzeUrl(
  url: string,
  allowCloudAI: boolean = false
): Promise<AnalyzeResponse> {
  const resp = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      url: url.trim(),
      source: 'dashboard',
      allow_cloud_ai: allowCloudAI,
    }),
  });

  if (!resp.ok) {
    const errorData = await resp.json().catch(() => ({}));
    throw new Error(errorData.detail || `Analysis request failed with status ${resp.status}`);
  }

  return resp.json();
}

export async function fetchHistory(limit: number = 50): Promise<ScanHistoryItem[]> {
  const resp = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!resp.ok) throw new Error(`Failed to load history: ${resp.status}`);
  return resp.json();
}

export async function fetchScanDetails(scanId: string): Promise<ScanDetailResponse> {
  const resp = await fetch(`${API_BASE}/history/${scanId}`);
  if (!resp.ok) throw new Error(`Failed to load scan details: ${resp.status}`);
  return resp.json();
}

export async function saveUserDecision(
  scanId: string,
  decision: 'PROCEED' | 'CANCEL'
): Promise<any> {
  const resp = await fetch(`${API_BASE}/decisions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      scan_id: scanId,
      decision: decision,
    }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to record decision: ${resp.status}`);
  }

  return resp.json();
}
