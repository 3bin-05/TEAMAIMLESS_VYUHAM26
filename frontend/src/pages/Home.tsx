import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { UrlInput } from '../components/scanner/UrlInput';
import { ScanProgress } from '../components/scanner/ScanProgress';
import { VerdictCard } from '../components/verdict/VerdictCard';
import { ThreatReport } from '../components/evidence/ThreatReport';
import { FeatureCardsBar } from '../components/home/FeatureCardsBar';
import { apiClient, ApiError } from '../services/api-client';
import type { AnalyzeResponse, ProviderStatus } from '../types/api';
import { AlertCircle, RefreshCw, Settings as SettingsIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Home: React.FC = () => {
  const [searchParams] = useSearchParams();
  const urlParam = searchParams.get('url');
  const navIdParam = searchParams.get('nav_id');
  const tabIdParam = searchParams.get('tab_id');

  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<AnalyzeResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isNetworkError, setIsNetworkError] = useState<boolean>(false);
  const [providerStatuses, setProviderStatuses] = useState<Record<string, ProviderStatus>>({});

  const sendExtensionAuthorization = (url: string, verdict: string) => {
    if (!navIdParam) return;
    const tabId = tabIdParam ? parseInt(tabIdParam, 10) : undefined;

    // Send via window.postMessage bridge to content script
    window.postMessage(
      {
        source: 'AEGIS_FRONTEND',
        type: 'AUTHORIZE_NAVIGATION',
        requestId: `req_${Date.now()}`,
        payload: {
          navId: navIdParam,
          tabId,
          url,
          verdict,
        },
      },
      '*'
    );

    // Also send via chrome.runtime if available
    try {
      if ((window as any).chrome?.runtime?.sendMessage) {
        (window as any).chrome.runtime.sendMessage({
          type: 'AUTHORIZE_NAVIGATION',
          payload: {
            navId: navIdParam,
            tabId,
            url,
            verdict,
          },
        });
      }
    } catch {
      // ignore
    }
  };

  const handleScan = async (url: string) => {
    setCurrentUrl(url);
    setIsLoading(true);
    setScanResult(null);
    setErrorMessage(null);
    setIsNetworkError(false);

    // Initial pending status for active scan
    setProviderStatuses({
      ml: 'pending',
      google_safe_browsing: 'pending',
      virustotal: 'pending',
      rdap: 'pending',
      domain_impersonation: 'pending',
      ai_explanation: 'pending',
    });

    try {
      const response = await apiClient.analyzeUrl(url, 'dashboard');
      setScanResult(response);

      // Extract real provider statuses from backend response
      const updatedStatuses: Record<string, ProviderStatus> = {};
      if (response.checks?.ml?.status) updatedStatuses.ml = response.checks.ml.status;
      if (response.checks?.google_safe_browsing?.status) {
        updatedStatuses.google_safe_browsing = response.checks.google_safe_browsing.status;
      }
      if (response.checks?.virustotal?.status) {
        updatedStatuses.virustotal = response.checks.virustotal.status;
      }
      if (response.checks?.rdap?.status) {
        updatedStatuses.rdap = response.checks.rdap.status;
      }
      if (response.domain_impersonation) {
        updatedStatuses.domain_impersonation = 'completed';
      }
      if (response.ai_explanation) {
        updatedStatuses.ai_explanation = 'completed';
      }

      setProviderStatuses(updatedStatuses);

      // Auto-authorize SAFE verdicts for the browser extension (Phase 5 & 6)
      const effectiveVerdict = response.ai_explanation?.risk_level || response.verdict;
      if (effectiveVerdict === 'safe' || response.verdict === 'SAFE') {
        sendExtensionAuthorization(url, 'SAFE');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
        setIsNetworkError(err.isNetworkError);
      } else {
        setErrorMessage('An unexpected error occurred while communicating with the analysis service.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-scan on mount if intercepted URL is present in query parameters
  useEffect(() => {
    if (urlParam && urlParam !== currentUrl && !scanResult && !isLoading) {
      handleScan(urlParam);
    }
  }, [urlParam]);

  const handleReset = () => {
    setScanResult(null);
    setErrorMessage(null);
    setIsNetworkError(false);
  };

  const handleProceedAtOwnRisk = () => {
    if (!currentUrl) return;
    sendExtensionAuthorization(currentUrl, 'SUSPICIOUS_PROCEED');
    window.location.href = currentUrl;
  };

  return (
    <div className="relative flex-1 flex flex-col items-center justify-center px-4 sm:px-6 py-1 overflow-hidden my-auto">
      <div className="relative z-10 w-full max-w-4xl mx-auto flex flex-col items-center">
        {/* Hero Section strictly matching user image */}
        {!scanResult && !isLoading && (
          <div className="text-center mb-2.5 sm:mb-3 max-w-2xl flex flex-col items-center">
            {/* Centered Large Gothic Shield Emblem */}
            <img
              src="/aegis-gothic-shield-emblem.png"
              alt="AEGIS Gothic Shield Emblem"
              className="w-32 h-32 sm:w-40 sm:h-40 md:w-44 md:h-44 object-contain mx-auto select-none drop-shadow-sm mb-2 sm:mb-2.5"
              draggable={false}
            />

            {/* Headline with wide tracking */}
            <h1
              className="text-[11px] sm:text-xs md:text-[13px] font-bold text-black uppercase tracking-[0.45em] sm:tracking-[0.55em] text-center select-none font-sans"
              style={{ letterSpacing: '0.45em' }}
            >
              BROWSE WITH CONFIDENCE
            </h1>
          </div>
        )}

        {/* URL Input Form */}
        {!scanResult && !isLoading && (
          <div className="w-full flex flex-col items-center">
            <UrlInput onScan={handleScan} isLoading={isLoading} />
            <FeatureCardsBar />
          </div>
        )}

        {/* Scan in Progress State */}
        {isLoading && (
          <ScanProgress url={currentUrl} providerStatuses={providerStatuses} />
        )}

        {/* Scan Result State */}
        {scanResult && !isLoading && (
          <div className="w-full space-y-8 animate-fadeIn">
            <VerdictCard
              verdict={scanResult.verdict}
              action={scanResult.action}
              riskScore={scanResult.risk_score}
              reason={scanResult.reason}
              reasons={scanResult.reasons}
              decisionDetails={scanResult.decision_details}
              confidenceLevel={scanResult.confidence_level}
              evidenceCompleteness={scanResult.evidence_completeness}
              url={scanResult.url}
              scanId={scanResult.scan_id}
              timestamp={scanResult.timestamp}
              aiExplanation={scanResult.ai_explanation}
              onReset={handleReset}
              onProceedAtOwnRisk={handleProceedAtOwnRisk}
              isExtensionContext={Boolean(navIdParam || urlParam)}
            />

            <ThreatReport
              checks={scanResult.checks}
              domainImpersonation={scanResult.domain_impersonation}
              aiExplanation={scanResult.ai_explanation}
              normalizedUrl={scanResult.normalized_url}
            />
          </div>
        )}

        {/* Error / Offline Backend State (Honest, strictly no mock data) */}
        {errorMessage && !isLoading && (
          <div className="w-full max-w-2xl mx-auto mt-6 p-6 rounded-2xl border border-amber-300 bg-white/90 backdrop-blur-md shadow-sm">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-amber-700 shrink-0 mt-0.5" />
              <div className="flex-1">
                <h2 className="text-sm font-bold text-amber-900">
                  {isNetworkError ? 'Backend Connection Required' : 'Analysis Service Error'}
                </h2>
                <p className="text-xs text-amber-800 mt-1 leading-relaxed">
                  {errorMessage}
                </p>

                {isNetworkError && (
                  <p className="text-xs text-amber-700 mt-2 font-mono bg-amber-50/70 p-2.5 rounded-lg border border-amber-200">
                    Backend Base URL: <strong>{apiClient.getBaseUrl()}</strong>
                    <br />
                    Ensure the AEGIS backend server is started, or update the API endpoint in Settings.
                  </p>
                )}

                <div className="mt-4 flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => handleScan(currentUrl)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-black hover:bg-neutral-800 text-white text-xs font-semibold shadow-xs transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Retry Request</span>
                  </button>

                  <Link
                    to="/settings"
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 text-xs font-semibold shadow-xs transition-colors"
                  >
                    <SettingsIcon className="w-3.5 h-3.5" />
                    <span>Configure Backend URL</span>
                  </Link>

                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-xs text-slate-600 hover:text-slate-900 font-medium ml-auto"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
