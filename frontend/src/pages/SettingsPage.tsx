import React, { useState, useEffect } from 'react';
import { apiClient } from '../services/api-client';
import type { HealthResponse } from '../types/api';
import { Database, Link2, Save, RotateCcw, Check, RefreshCw } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [apiUrl, setApiUrl] = useState<string>(apiClient.getBaseUrl());
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);
  const [healthLoading, setHealthLoading] = useState<boolean>(false);
  const [healthData, setHealthData] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);

  const checkHealth = async () => {
    setHealthLoading(true);
    setHealthError(null);
    setHealthData(null);
    try {
      const data = await apiClient.checkHealth();
      setHealthData(data);
    } catch (err) {
      setHealthError(err instanceof Error ? err.message : 'Failed to fetch');
    } finally {
      setHealthLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  const handleSaveApiUrl = (e: React.FormEvent) => {
    e.preventDefault();
    apiClient.setBaseUrl(apiUrl);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
    checkHealth();
  };

  const handleResetApiUrl = () => {
    const defaultUrl = 'http://localhost:8000';
    setApiUrl(defaultUrl);
    apiClient.setBaseUrl(defaultUrl);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
    checkHealth();
  };

  return (
    <div className="flex-1 w-full max-w-4xl mx-auto px-4 sm:px-6 py-12">
      {/* Header */}
      <div className="mb-8">
        <div className="text-[11px] font-bold text-neutral-500 uppercase tracking-widest mb-1">
          CONFIGURATION
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-neutral-900 tracking-tight mb-2">
          System Settings &amp; Status
        </h1>
        <p className="text-sm text-neutral-500">
          Configure backend connectivity and monitor the runtime health of AEGIS.
        </p>
      </div>

      <div className="space-y-6">
        {/* 1. BACKEND API ENDPOINT CARD */}
        <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] p-6 sm:p-7 space-y-5">
          {/* Top Info Row */}
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center shrink-0 text-neutral-800">
              <Database className="w-6 h-6 text-neutral-800" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold text-neutral-900 uppercase tracking-wider mb-1">
                BACKEND API ENDPOINT
              </h2>
              <p className="text-xs text-neutral-500 leading-relaxed">
                The dashboard and extension communicate directly with the AEGIS FastAPI backend REST endpoints.
              </p>
              <p className="text-xs text-neutral-500 leading-relaxed mt-0.5">
                Configure the base URL here (defaults to{' '}
                <code className="bg-neutral-100 px-1 py-0.5 rounded text-[11px] font-mono text-neutral-700">
                  http://localhost:8000
                </code>
                ).
              </p>
            </div>
          </div>

          {/* Form / Inputs Row */}
          <form onSubmit={handleSaveApiUrl} className="space-y-2">
            <div className="flex flex-col sm:flex-row items-center gap-3">
              {/* Link Icon Box */}
              <div className="hidden sm:flex w-10 h-10 rounded-xl bg-neutral-50 border border-neutral-200/80 items-center justify-center shrink-0 text-neutral-700">
                <Link2 className="w-4 h-4 text-neutral-700" />
              </div>

              {/* URL Input */}
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="http://localhost:8000"
                className="w-full sm:flex-1 h-10 px-3.5 text-xs font-mono bg-white border border-neutral-200/90 rounded-xl text-neutral-900 focus:outline-none focus:border-neutral-400 focus:ring-1 focus:ring-neutral-200"
              />

              {/* Save & Connect Button */}
              <button
                type="submit"
                className="w-full sm:w-auto h-10 px-4 rounded-xl bg-neutral-950 hover:bg-black text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-xs transition-colors shrink-0"
              >
                <Save className="w-3.5 h-3.5 text-white" />
                <span>Save &amp; Connect</span>
              </button>

              {/* Reset Default Button */}
              <button
                type="button"
                onClick={handleResetApiUrl}
                className="w-full sm:w-auto h-10 px-4 rounded-xl bg-white hover:bg-neutral-50 border border-neutral-200/90 text-neutral-700 text-xs font-semibold transition-colors shrink-0 shadow-xs"
              >
                Reset Default
              </button>
            </div>

            {savedSuccess && (
              <p className="text-xs text-emerald-600 font-medium flex items-center gap-1.5 pt-1">
                <Check className="w-3.5 h-3.5" />
                <span>API endpoint updated and saved successfully.</span>
              </p>
            )}
          </form>
        </div>

        {/* 2. LIVE BACKEND HEALTH DIAGNOSTIC CARD */}
        <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] p-6 sm:p-7 space-y-5">
          {/* Top Info Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-start sm:items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center shrink-0 text-neutral-800">
                <svg
                  className="w-6 h-6 text-neutral-800"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
                  <path d="M8 12h2l1-2 2 4 1-2h2" />
                </svg>
              </div>
              <div>
                <h2 className="text-sm font-extrabold text-neutral-900 uppercase tracking-wider mb-1">
                  LIVE BACKEND HEALTH DIAGNOSTIC
                </h2>
                <p className="text-xs text-neutral-500">
                  Check if the AEGIS backend service is running and responding.
                </p>
              </div>
            </div>

            {/* Test Connection Button */}
            <button
              type="button"
              onClick={checkHealth}
              disabled={healthLoading}
              className="h-10 px-4 rounded-xl bg-neutral-950 hover:bg-black text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-xs transition-colors shrink-0 self-start sm:self-auto"
            >
              <RotateCcw className={`w-3.5 h-3.5 text-white ${healthLoading ? 'animate-spin' : ''}`} />
              <span>Test Connection</span>
            </button>
          </div>

          {/* Diagnostic Status Banner */}
          {healthLoading && (
            <div className="p-4 sm:p-5 bg-neutral-50/90 border border-neutral-200/90 rounded-xl flex items-center gap-3 text-neutral-700 text-xs shadow-xs">
              <RefreshCw className="w-4 h-4 animate-spin text-black shrink-0" />
              <span>Testing connection to AEGIS backend at {apiUrl}...</span>
            </div>
          )}

          {!healthLoading && healthData && (
            <div className="p-4 sm:p-5 bg-neutral-50/90 border border-neutral-200/90 rounded-xl flex items-start gap-4 shadow-xs">
              <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center font-bold text-sm shrink-0 shadow-xs mt-0.5">
                <Check className="w-4 h-4 text-white stroke-[2.5]" />
              </div>
              <div className="space-y-1">
                <div className="font-bold text-sm text-black leading-snug">
                  Backend Service Active &amp; Responsive
                </div>
                <div className="text-xs text-neutral-600 leading-relaxed font-sans">
                  Successfully connected to AEGIS FastAPI backend at {apiUrl}.
                </div>
                <div className="text-xs text-neutral-500 leading-relaxed pt-0.5 font-mono text-[11px]">
                  Status: {healthData.status || 'healthy'} &middot; Version: {healthData.version || '1.0.0'}
                </div>
              </div>
            </div>
          )}

          {!healthLoading && !healthData && (
            <div className="p-4 sm:p-5 bg-neutral-50/90 border border-neutral-200/90 rounded-xl flex items-start gap-4 shadow-xs">
              <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center font-extrabold text-sm shrink-0 shadow-xs select-none mt-0.5">
                !
              </div>
              <div className="space-y-1">
                <div className="font-bold text-sm text-black leading-snug">
                  Backend Service Unreachable
                </div>
                <div className="text-xs text-neutral-600 leading-relaxed font-sans">
                  {healthError || `Unable to connect to AEGIS backend at ${apiUrl}. Please verify the service is running. (Failed to fetch)`}
                </div>
                <div className="text-xs text-neutral-500 leading-relaxed pt-1">
                  Ensure your backend developer has launched the FastAPI server (e.g.{' '}
                  <code className="bg-neutral-200/80 text-black font-mono text-[11px] font-semibold px-2 py-0.5 rounded border border-neutral-300/70">
                    uvicorn main:app --port 8000
                  </code>
                  ).
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
