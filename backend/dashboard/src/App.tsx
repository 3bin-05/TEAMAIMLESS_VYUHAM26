import React, { useEffect, useState, useMemo } from 'react';
import {
  fetchHealth,
  fetchAIStatus,
  analyzeUrl,
  fetchHistory,
  fetchScanDetails,
  saveUserDecision,
} from './api';
import type {
  HealthResponse,
  AIStatusResponse,
  AnalyzeResponse,
  ScanHistoryItem,
  ScanDetailResponse,
} from './types';

export default function App() {
  // Global backend state
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [aiStatus, setAIStatus] = useState<AIStatusResponse | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Scanner state
  const [inputUrl, setInputUrl] = useState('');
  const [allowCloudAI, setAllowCloudAI] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState<AnalyzeResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // History filtering
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');

  // Detail Modal state
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [decisionNotice, setDecisionNotice] = useState<string | null>(null);

  // Active detail tab
  const [activeTab, setActiveTab] = useState<'domain_shield' | 'ml' | 'gsb' | 'vt' | 'rdap' | 'ai'>('domain_shield');

  // Initial load
  useEffect(() => {
    loadHealthAndAI();
    loadHistory();
  }, []);

  async function loadHealthAndAI() {
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch (e) {
      console.warn('Health check unreachable:', e);
    }

    try {
      const ai = await fetchAIStatus();
      setAIStatus(ai);
    } catch (e) {
      console.warn('AI status check unreachable:', e);
    }
  }

  async function loadHistory() {
    setLoadingHistory(true);
    try {
      const hist = await fetchHistory(50);
      setHistory(hist);
    } catch (e) {
      console.warn('History fetch error:', e);
    } finally {
      setLoadingHistory(false);
    }
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!inputUrl.trim()) return;

    setScanning(true);
    setScanError(null);
    setCurrentResult(null);

    try {
      const result = await analyzeUrl(inputUrl, allowCloudAI);
      setCurrentResult(result);
      // Refresh history to reflect newly persisted record
      loadHistory();
    } catch (err: any) {
      setScanError(err.message || 'Analysis failed. Please verify that the backend is running.');
    } finally {
      setScanning(false);
    }
  }

  async function openDetailModal(scanId: string) {
    setSelectedScanId(scanId);
    setDetailLoading(true);
    setDecisionNotice(null);
    try {
      const detail = await fetchScanDetails(scanId);
      setScanDetail(detail);
    } catch (err: any) {
      console.error('Failed to load scan detail:', err);
    } finally {
      setDetailLoading(false);
    }
  }

  async function handleRecordDecision(decision: 'PROCEED' | 'CANCEL') {
    if (!selectedScanId) return;
    try {
      await saveUserDecision(selectedScanId, decision);
      setDecisionNotice(`Decision '${decision}' recorded in database successfully.`);
    } catch (err: any) {
      setDecisionNotice(`Failed to save decision: ${err.message}`);
    }
  }

  // Filtered history
  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesSearch =
        item.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.scan_id.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesVerdict = verdictFilter === 'ALL' || item.verdict === verdictFilter;
      return matchesSearch && matchesVerdict;
    });
  }, [history, searchTerm, verdictFilter]);

  // Telemetry aggregates from real history
  const stats = useMemo(() => {
    const total = history.length;
    const safe = history.filter((h) => h.verdict === 'SAFE').length;
    const suspicious = history.filter((h) => h.verdict === 'SUSPICIOUS').length;
    const critical = history.filter((h) => h.verdict === 'CRITICAL').length;
    const insufficient = history.filter((h) => h.verdict === 'INSUFFICIENT_EVIDENCE').length;
    return { total, safe, suspicious, critical, insufficient };
  }, [history]);

  function getVerdictBadgeClass(v?: string) {
    const verdict = (v || '').toUpperCase();
    if (verdict === 'SAFE') return 'badge-safe';
    if (verdict === 'SUSPICIOUS') return 'badge-suspicious';
    if (verdict === 'CRITICAL') return 'badge-critical';
    return 'badge-insufficient';
  }

  function getScoreColor(score: number) {
    if (score >= 70) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#10b981';
  }

  return (
    <div style={{ maxWidth: '1240px', margin: '0 auto', padding: '24px 20px 60px' }}>
      {/* Top Navbar */}
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          paddingBottom: '20px',
          marginBottom: '24px',
          borderBottom: '1px solid var(--border-subtle)',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '20px',
              boxShadow: '0 0 15px rgba(56, 189, 248, 0.4)',
            }}
          >
            🛡️
          </div>
          <div>
            <h1 style={{ fontSize: '20px', fontWeight: 800, letterSpacing: '0.5px' }}>
              AEGIS <span style={{ color: 'var(--accent-cyan)', fontWeight: 400 }}>| AI Security Platform</span>
            </h1>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Deterministic Threat Intelligence & Brand Impersonation Defense
            </p>
          </div>
        </div>

        {/* System Status Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <div
            className="glass-panel"
            style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', fontSize: '12px' }}
          >
            <div
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: health?.status === 'healthy' ? '#10b981' : '#ef4444',
                boxShadow: health?.status === 'healthy' ? '0 0 8px #10b981' : 'none',
              }}
            />
            <span>API: {health ? health.status.toUpperCase() : 'CONNECTING...'}</span>
          </div>

          <div
            className="glass-panel"
            style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', fontSize: '12px' }}
          >
            <span style={{ color: 'var(--text-secondary)' }}>Hybrid AI:</span>
            <span style={{ fontWeight: 600, color: aiStatus?.ollama_available ? '#34d399' : '#fbbf24' }}>
              {aiStatus?.ollama_available ? 'OLLAMA READY' : 'AI ADVISORY'}
            </span>
          </div>
        </div>
      </header>

      {/* Overview Metric Cards */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '28px' }}>
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: 600 }}>
            Total Scans Logged
          </div>
          <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '4px', color: 'var(--text-primary)' }}>
            {stats.total}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Persisted in SQLite database
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#34d399', fontWeight: 600 }}>
            Verified Safe URLs
          </div>
          <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '4px', color: '#34d399' }}>
            {stats.safe}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Passed all 5 core integrity checks
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fbbf24', fontWeight: 600 }}>
            Suspicious Targets
          </div>
          <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '4px', color: '#fbbf24' }}>
            {stats.suspicious}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Heuristic or brand mimicry flags
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#f87171', fontWeight: 600 }}>
            Critical Phishing Threats
          </div>
          <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '4px', color: '#f87171' }}>
            {stats.critical}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Confirmed GSB or VT consensus
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: 600 }}>
            Insufficient Evidence
          </div>
          <div style={{ fontSize: '28px', fontWeight: 800, marginTop: '4px', color: 'var(--text-secondary)' }}>
            {stats.insufficient}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Conservative fallback state
          </div>
        </div>
      </section>

      {/* URL Scanner Section */}
      <section className="glass-panel" style={{ padding: '24px', marginBottom: '32px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '6px', color: 'var(--accent-cyan)' }}>
          🔍 Real-Time URL Threat & Brand Impersonation Scanner
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          Executes concurrent inspection across PhishOFE ML feature extraction, Google Safe Browsing, VirusTotal consensus, RDAP registration age, and DomainShield typosquatting analysis.
        </p>

        <form onSubmit={handleScan}>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
            <div style={{ flex: '1', minWidth: '280px' }}>
              <input
                type="text"
                placeholder="Enter URL to analyze (e.g. https://google.com or https://g00gle.com/login)"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                disabled={scanning}
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={scanning || !inputUrl.trim()}>
              {scanning ? (
                <>
                  <div className="spinner" />
                  <span>Analyzing Destination...</span>
                </>
              ) : (
                <>
                  <span>Scan with AEGIS</span>
                </>
              )}
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={allowCloudAI}
                onChange={(e) => setAllowCloudAI(e.target.checked)}
                disabled={scanning}
              />
              <span>Allow Advisory Cloud AI Analysis (Anthropic Claude - Dual Consent Enforced)</span>
            </label>

            {/* Quick sample buttons for hackathon demonstration */}
            <div style={{ display: 'flex', gap: '6px', fontSize: '11px' }}>
              <span style={{ color: 'var(--text-muted)', alignSelf: 'center' }}>Test Fixtures:</span>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => setInputUrl('https://google.com')}
              >
                Official Brand
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => setInputUrl('https://g00gle.com/account/login')}
              >
                Typosquatting
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '11px' }}
                onClick={() => setInputUrl('http://paypal-account-verify.com')}
              >
                Keyword Spoof
              </button>
            </div>
          </div>
        </form>

        {scanError && (
          <div
            style={{
              marginTop: '16px',
              padding: '12px 16px',
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              borderRadius: '8px',
              color: '#fca5a5',
              fontSize: '13px',
            }}
          >
            ⚠️ {scanError}
          </div>
        )}

        {/* Live Analysis Results Card */}
        {currentResult && (
          <div
            style={{
              marginTop: '24px',
              padding: '20px',
              background: 'rgba(13, 19, 34, 0.95)',
              borderRadius: '10px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {/* Header info */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span className={`badge ${getVerdictBadgeClass(currentResult.verdict)}`}>
                  {currentResult.verdict}
                </span>
                <span style={{ marginLeft: '10px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Recommended Action: <strong style={{ color: 'var(--text-primary)' }}>{currentResult.action}</strong>
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                Scan ID: {currentResult.scan_id}
              </div>
            </div>

            {/* Score & Summary Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '20px' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Risk Score Index
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '4px' }}>
                  <span style={{ fontSize: '32px', fontWeight: 800, color: getScoreColor(currentResult.risk_score) }}>
                    {currentResult.risk_score}
                  </span>
                  <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>/ 100</span>
                </div>
                <div className="risk-meter">
                  <div
                    className="risk-meter-fill"
                    style={{
                      width: `${currentResult.risk_score}%`,
                      background: getScoreColor(currentResult.risk_score),
                    }}
                  />
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Deterministic Policy Reason
                </div>
                <div style={{ fontSize: '13px', marginTop: '6px', lineHeight: 1.4, color: 'var(--text-primary)' }}>
                  {currentResult.reason}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  Evidence Completeness
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, marginTop: '4px', color: 'var(--accent-cyan)' }}>
                  {Math.round((currentResult.evidence_completeness || 0) * 100)}%
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Confidence: {currentResult.confidence_level || 'MEDIUM'}
                </div>
              </div>
            </div>

            {/* Provider Evidence Details Tabs */}
            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
              <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className={`btn ${activeTab === 'domain_shield' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('domain_shield')}
                >
                  🛡️ DomainShield
                </button>
                <button
                  type="button"
                  className={`btn ${activeTab === 'ml' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('ml')}
                >
                  🤖 PhishOFE ML
                </button>
                <button
                  type="button"
                  className={`btn ${activeTab === 'gsb' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('gsb')}
                >
                  🌐 Safe Browsing
                </button>
                <button
                  type="button"
                  className={`btn ${activeTab === 'vt' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('vt')}
                >
                  🦠 VirusTotal
                </button>
                <button
                  type="button"
                  className={`btn ${activeTab === 'rdap' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('rdap')}
                >
                  📅 RDAP Registry
                </button>
                <button
                  type="button"
                  className={`btn ${activeTab === 'ai' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => setActiveTab('ai')}
                >
                  🧠 Advisory AI
                </button>
              </div>

              {/* Tab Contents */}
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '16px', borderRadius: '8px', fontSize: '13px', minHeight: '140px' }}>
                {activeTab === 'domain_shield' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      DomainShield Impersonation Analysis
                    </h3>
                    {currentResult.domain_impersonation ? (
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                        <div>
                          <strong>Target Brand:</strong> {currentResult.domain_impersonation.matched_brand || 'None'}
                        </div>
                        <div>
                          <strong>Impersonation Detected:</strong>{' '}
                          <span style={{ color: currentResult.domain_impersonation.impersonation_detected ? '#f87171' : '#34d399', fontWeight: 700 }}>
                            {currentResult.domain_impersonation.impersonation_detected ? 'YES (ALERT)' : 'NO (CLEAN)'}
                          </span>
                        </div>
                        <div>
                          <strong>Similarity Score:</strong> {currentResult.domain_impersonation.similarity_score}%
                        </div>
                        <div>
                          <strong>Techniques:</strong>{' '}
                          {currentResult.domain_impersonation.detection_techniques?.join(', ') || 'None'}
                        </div>
                        <div style={{ gridColumn: '1 / -1', marginTop: '6px' }}>
                          <strong>Evidence:</strong>
                          <ul style={{ paddingLeft: '20px', marginTop: '4px', color: 'var(--text-secondary)' }}>
                            {currentResult.domain_impersonation.supporting_evidence?.map((ev, i) => (
                              <li key={i}>{ev}</li>
                            )) || <li>No corroborating evidence points recorded.</li>}
                          </ul>
                        </div>
                      </div>
                    ) : (
                      <p style={{ color: 'var(--text-muted)' }}>No DomainShield telemetry recorded.</p>
                    )}
                  </div>
                )}

                {activeTab === 'ml' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      PhishOFE Random Forest Model (URL-Only Lexical/Structural)
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                      <div>
                        <strong>Prediction:</strong>{' '}
                        <span style={{ fontWeight: 700, color: currentResult.checks.ml?.details?.prediction === 'phishing' ? '#f87171' : '#34d399' }}>
                          {currentResult.checks.ml?.details?.prediction?.toUpperCase() || 'UNKNOWN'}
                        </span>
                      </div>
                      <div>
                        <strong>Confidence:</strong>{' '}
                        {currentResult.checks.ml?.details?.confidence
                          ? `${Math.round(currentResult.checks.ml.details.confidence * 100)}%`
                          : 'N/A'}
                      </div>
                      <div>
                        <strong>Phishing Probability:</strong>{' '}
                        {currentResult.checks.ml?.details?.phishing_probability !== undefined
                          ? `${(currentResult.checks.ml.details.phishing_probability * 100).toFixed(1)}%`
                          : 'N/A'}
                      </div>
                      <div>
                        <strong>Status:</strong> {currentResult.checks.ml?.status || 'unavailable'}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'gsb' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      Google Safe Browsing (Lookup API v4)
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                      <div>
                        <strong>Threat Detected:</strong>{' '}
                        <span style={{ fontWeight: 700, color: currentResult.checks.google_safe_browsing?.details?.threat_detected ? '#f87171' : '#34d399' }}>
                          {currentResult.checks.google_safe_browsing?.details?.threat_detected ? 'YES (CRITICAL)' : 'NO'}
                        </span>
                      </div>
                      <div>
                        <strong>Status:</strong> {currentResult.checks.google_safe_browsing?.status || 'unavailable'}
                      </div>
                      <div>
                        <strong>Matches Count:</strong> {currentResult.checks.google_safe_browsing?.details?.match_count || 0}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'vt' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      VirusTotal Multi-Engine Threat Intelligence
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                      <div>
                        <strong>Malicious Engines:</strong>{' '}
                        <span style={{ color: (currentResult.checks.virustotal?.details?.malicious || 0) > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                          {currentResult.checks.virustotal?.details?.malicious ?? '0'}
                        </span>
                      </div>
                      <div>
                        <strong>Suspicious Engines:</strong> {currentResult.checks.virustotal?.details?.suspicious ?? '0'}
                      </div>
                      <div>
                        <strong>Total Engines:</strong> {currentResult.checks.virustotal?.details?.total ?? '0'}
                      </div>
                      <div>
                        <strong>Status:</strong> {currentResult.checks.virustotal?.status || 'pending'}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'rdap' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      RDAP Domain Registration Intelligence
                    </h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                      <div>
                        <strong>Domain Age:</strong>{' '}
                        {currentResult.checks.rdap?.details?.domain_age_days !== undefined
                          ? `${currentResult.checks.rdap.details.domain_age_days} days`
                          : 'Unknown'}
                      </div>
                      <div>
                        <strong>Registrar:</strong> {currentResult.checks.rdap?.details?.registrar || 'Not available'}
                      </div>
                      <div>
                        <strong>Creation Date:</strong> {currentResult.checks.rdap?.details?.creation_date || 'Unknown'}
                      </div>
                      <div>
                        <strong>Status:</strong> {currentResult.checks.rdap?.status || 'unavailable'}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'ai' && (
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                      Hybrid AI Advisory Layer (Advisory Only)
                    </h3>
                    {currentResult.ai_explanation?.short_explanation ? (
                      <div>
                        <p style={{ marginBottom: '10px', color: 'var(--text-primary)' }}>
                          <strong>Explanation:</strong> {currentResult.ai_explanation.short_explanation}
                        </p>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', fontSize: '12px' }}>
                          <div>
                            <strong>Provider:</strong> {currentResult.ai_explanation.provider}
                          </div>
                          <div>
                            <strong>Model:</strong> {currentResult.ai_explanation.model}
                          </div>
                          <div>
                            <strong>Latency:</strong> {currentResult.ai_explanation.latency_ms?.toFixed(0)} ms
                          </div>
                          <div>
                            <strong>Recommendation:</strong> {currentResult.ai_explanation.recommended_action || 'N/A'}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <p style={{ color: 'var(--text-muted)' }}>
                        AI explanation layer unavailable or unconfigured (Local Ollama offline and Cloud AI not permitted). Deterministic risk score and verdict remain fully authoritative.
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Scan History Section */}
      <section className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              📋 Comprehensive Scan Audit Trail
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Real historical scans retrieved from SQLite persistence
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <input
              type="text"
              placeholder="Search by domain or URL..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ width: '220px', padding: '7px 12px', fontSize: '12px' }}
            />

            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              style={{ width: '150px', padding: '7px 10px', fontSize: '12px' }}
            >
              <option value="ALL">All Verdicts</option>
              <option value="SAFE">SAFE</option>
              <option value="SUSPICIOUS">SUSPICIOUS</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="INSUFFICIENT_EVIDENCE">INSUFFICIENT</option>
            </select>

            <button type="button" className="btn btn-secondary" onClick={loadHistory} disabled={loadingHistory}>
              {loadingHistory ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {/* History Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-secondary)', fontSize: '11px', textTransform: 'uppercase' }}>
                <th style={{ padding: '10px 12px' }}>Timestamp</th>
                <th style={{ padding: '10px 12px' }}>Target URL / Host</th>
                <th style={{ padding: '10px 12px' }}>Verdict</th>
                <th style={{ padding: '10px 12px' }}>Risk Score</th>
                <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No scan records match the current filter.
                  </td>
                </tr>
              ) : (
                filteredHistory.map((item) => (
                  <tr
                    key={item.scan_id}
                    style={{ borderBottom: '1px solid rgba(51, 65, 85, 0.3)', transition: 'background 0.15s ease' }}
                  >
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '10px 12px', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span style={{ fontWeight: 600 }}>{item.domain}</span>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{item.url}</div>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span className={`badge ${getVerdictBadgeClass(item.verdict)}`}>
                        {item.verdict}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ fontWeight: 700, color: getScoreColor(item.risk_score) }}>
                        {item.risk_score}
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}> / 100</span>
                    </td>
                    <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ padding: '4px 10px', fontSize: '11px' }}
                        onClick={() => openDetailModal(item.scan_id)}
                      >
                        Inspect Evidence
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Scan Detail & Decision Modal */}
      {selectedScanId && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: '100%',
              maxWidth: '680px',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '24px',
              background: '#0d1322',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                Scan Telemetry & Evidence Breakdown
              </h3>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ padding: '4px 8px', fontSize: '12px' }}
                onClick={() => setSelectedScanId(null)}
              >
                ✕ Close
              </button>
            </div>

            {detailLoading ? (
              <div style={{ padding: '40px', textAlign: 'center' }}>
                <div className="spinner" style={{ margin: '0 auto 10px' }} />
                <span>Loading complete record telemetry...</span>
              </div>
            ) : scanDetail ? (
              <div>
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Target URL:</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, wordBreak: 'break-all' }}>{scanDetail.original_url}</div>
                </div>

                <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
                  <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Verdict:</div>
                    <span className={`badge ${getVerdictBadgeClass(scanDetail.verdict)}`} style={{ marginTop: '4px' }}>
                      {scanDetail.verdict}
                    </span>
                  </div>
                  <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Risk Score:</div>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: getScoreColor(scanDetail.risk_score), marginTop: '2px' }}>
                      {scanDetail.risk_score} / 100
                    </div>
                  </div>
                  <div style={{ flex: 1, background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Recommended Action:</div>
                    <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                      {scanDetail.action}
                    </div>
                  </div>
                </div>

                {/* Factors breakdown */}
                {scanDetail.decision_details && (
                  <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '14px', borderRadius: '8px', marginBottom: '16px', fontSize: '12px' }}>
                    <h4 style={{ fontSize: '13px', fontWeight: 700, marginBottom: '6px', color: 'var(--text-primary)' }}>
                      Decision Explainability Breakdown
                    </h4>
                    {scanDetail.decision_details.supporting_factors && scanDetail.decision_details.supporting_factors.length > 0 && (
                      <div style={{ marginBottom: '8px' }}>
                        <span style={{ color: '#f87171', fontWeight: 600 }}>Supporting Threat Signals:</span>
                        <ul style={{ paddingLeft: '18px', marginTop: '2px' }}>
                          {scanDetail.decision_details.supporting_factors.map((f, i) => (
                            <li key={i}>{f}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {scanDetail.decision_details.benign_factors && scanDetail.decision_details.benign_factors.length > 0 && (
                      <div style={{ marginBottom: '8px' }}>
                        <span style={{ color: '#34d399', fontWeight: 600 }}>Benign / Trust Indicators:</span>
                        <ul style={{ paddingLeft: '18px', marginTop: '2px' }}>
                          {scanDetail.decision_details.benign_factors.map((f, i) => (
                            <li key={i}>{f}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {scanDetail.decision_details.missing_factors && scanDetail.decision_details.missing_factors.length > 0 && (
                      <div>
                        <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Missing / Pending Providers:</span>
                        <ul style={{ paddingLeft: '18px', marginTop: '2px', color: 'var(--text-muted)' }}>
                          {scanDetail.decision_details.missing_factors.map((f, i) => (
                            <li key={i}>{f}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* Record User Decision Action */}
                <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    Record User Navigation Decision (Override Telemetry):
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      className="btn"
                      style={{ background: '#065f46', borderColor: '#059669', color: '#34d399' }}
                      onClick={() => handleRecordDecision('PROCEED')}
                    >
                      ✓ Proceed (User Override)
                    </button>
                    <button
                      type="button"
                      className="btn"
                      style={{ background: '#7f1d1d', borderColor: '#b91c1c', color: '#f87171' }}
                      onClick={() => handleRecordDecision('CANCEL')}
                    >
                      ✕ Cancel Navigation (Safe)
                    </button>
                  </div>
                  {decisionNotice && (
                    <div style={{ marginTop: '8px', fontSize: '12px', color: 'var(--accent-cyan)' }}>
                      {decisionNotice}
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
