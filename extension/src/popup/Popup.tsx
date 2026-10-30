import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  ExternalLink,
  Settings,
  RefreshCw,
  Server,
  ArrowRight,
  Lock,
  Link2,
} from 'lucide-react';
import type { AnalyzeResponse, Verdict } from '../types/extension';

export const Popup: React.FC = () => {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<AnalyzeResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');

  useEffect(() => {
    // Check backend health via background service worker
    chrome.runtime.sendMessage({ type: 'HEALTH_CHECK' }, (res) => {
      setBackendOnline(res?.online ?? false);
    });

    // Get current configured URL
    chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (res) => {
      if (res?.baseUrl) setApiUrl(res.baseUrl);
    });
  }, []);

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() || isScanning) return;

    setIsScanning(true);
    setScanResult(null);
    setErrorMessage(null);

    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_URL',
        payload: { url: urlInput.trim(), source: 'chrome_extension' },
      },
      (res) => {
        setIsScanning(false);
        if (!res || !res.success) {
          setErrorMessage(res?.error || 'Unable to connect to AEGIS backend.');
        } else {
          setScanResult(res.data as AnalyzeResponse);
        }
      }
    );
  };

  const handleSaveApiUrl = (e: React.FormEvent) => {
    e.preventDefault();
    chrome.runtime.sendMessage(
      {
        type: 'SET_CONFIG',
        payload: { baseUrl: apiUrl.trim() },
      },
      () => {
        chrome.runtime.sendMessage({ type: 'HEALTH_CHECK' }, (res) => {
          setBackendOnline(res?.online ?? false);
        });
        setShowSettings(false);
      }
    );
  };

  const openDashboard = () => {
    chrome.tabs.create({ url: 'http://localhost:3000' });
  };

  const getVerdictBadge = (verdict: Verdict) => {
    switch (verdict) {
      case 'SAFE':
        return (
          <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-900 flex items-start gap-2.5 shadow-xs">
            <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-xs uppercase tracking-wider text-emerald-800">Verified Safe</div>
              <div className="text-xs text-emerald-700 mt-0.5 leading-relaxed">
                {scanResult?.reason || 'No active threats detected.'}
              </div>
            </div>
          </div>
        );
      case 'SUSPICIOUS':
        return (
          <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-amber-900 flex items-start gap-2.5 shadow-xs">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-xs uppercase tracking-wider text-amber-800">Suspicious Indicators</div>
              <div className="text-xs text-amber-700 mt-0.5 leading-relaxed">
                {scanResult?.reason || 'Caution advised. Possible deceptive characteristics.'}
              </div>
            </div>
          </div>
        );
      case 'CRITICAL':
        return (
          <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-red-900 flex items-start gap-2.5 shadow-xs">
            <ShieldAlert className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-xs uppercase tracking-wider text-red-800">Malicious Threat Blocked</div>
              <div className="text-xs text-red-700 mt-0.5 leading-relaxed">
                {scanResult?.reason || 'High-confidence phishing threat.'}
              </div>
            </div>
          </div>
        );
      default:
        return (
          <div className="p-3 bg-slate-100 border border-slate-200 rounded-xl text-slate-800 text-xs">
            Unable to verify destination.
          </div>
        );
    }
  };

  return (
    <div className="w-[360px] bg-white text-slate-900 font-sans p-4 select-none border border-slate-200/80 shadow-2xl">
      {/* Top Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-200/80">
        <div className="flex items-center gap-2.5">
          <img src="/aegis-gothic-shield-emblem.png" alt="AEGIS Emblem" className="w-7 h-7 object-contain shrink-0" />
          <div>
            <div className="font-black text-sm tracking-wider uppercase text-black leading-tight">AEGIS</div>
            <div className="text-[9px] text-slate-500 font-bold tracking-widest uppercase">AI Browser Defense</div>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setShowSettings(!showSettings)}
            className="p-1.5 rounded-lg hover:bg-slate-100 text-slate-600 transition-colors"
            title="Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Backend Status Bar */}
      <div className="my-3 flex items-center justify-between px-3 py-1.5 rounded-full bg-slate-50 border border-slate-200/90 text-xs">
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${
              backendOnline === true
                ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.5)]'
                : backendOnline === false
                ? 'bg-amber-500'
                : 'bg-slate-300 animate-pulse'
            }`}
          />
          <span className="font-semibold text-slate-800">
            {backendOnline === true
              ? 'Defense Engine Active'
              : backendOnline === false
              ? 'Backend Offline'
              : 'Connecting...'}
          </span>
        </div>
        <span className="text-[10px] font-mono font-medium text-slate-400">MV3 Active</span>
      </div>

      {/* Settings Form */}
      {showSettings ? (
        <form onSubmit={handleSaveApiUrl} className="bg-slate-50 p-3 rounded-xl border border-slate-200 mb-3 space-y-2">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-900">
            <Server className="w-3.5 h-3.5 text-black" />
            <span>Backend API Base URL</span>
          </div>
          <input
            type="text"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            className="w-full px-2.5 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-lg focus:outline-none focus:border-black"
          />
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => setShowSettings(false)}
              className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-3 py-1 bg-black text-white text-xs font-bold rounded-lg hover:bg-neutral-800"
            >
              Save
            </button>
          </div>
        </form>
      ) : (
        <>
          {/* Quick Check Form */}
          <form onSubmit={handleScan} className="my-3">
            <div className="relative flex items-center bg-white border border-slate-200/90 rounded-xl shadow-xs focus-within:border-black p-1">
              <Link2 className="w-4 h-4 text-slate-500 ml-2 shrink-0" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Check link (https://...)"
                disabled={isScanning}
                className="w-full pl-2 pr-2 py-1.5 text-xs text-slate-900 bg-transparent focus:outline-none"
              />
              <button
                type="submit"
                disabled={isScanning}
                className="shrink-0 px-3 py-1.5 bg-black hover:bg-neutral-800 text-white text-xs font-bold rounded-lg flex items-center gap-1 transition-all"
              >
                {isScanning ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <>
                    <Search className="w-3 h-3" />
                    <span>Check</span>
                    <ArrowRight className="w-3 h-3" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Result or Error */}
          {scanResult && <div className="mb-3">{getVerdictBadge(scanResult.verdict)}</div>}

          {errorMessage && (
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-amber-900 text-xs mb-3">
              <div className="font-bold mb-0.5">Connection Notice</div>
              <div className="leading-relaxed">{errorMessage}</div>
            </div>
          )}
        </>
      )}

      {/* Action Footer */}
      <div className="pt-2.5 border-t border-slate-200/80 flex items-center justify-between">
        <button
          type="button"
          onClick={openDashboard}
          className="inline-flex items-center gap-1.5 text-xs font-bold text-black hover:text-neutral-700"
        >
          <span>Open Full Dashboard</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </button>

        <div className="flex items-center gap-1 text-[11px] text-slate-500 font-medium">
          <Lock className="w-3 h-3" />
          <span>Zero Secrets</span>
        </div>
      </div>
    </div>
  );
};
