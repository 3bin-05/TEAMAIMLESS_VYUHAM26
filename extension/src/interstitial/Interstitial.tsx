import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ArrowLeft,
  ExternalLink,
  Loader2,
  Lock,
} from 'lucide-react';
import type { AnalyzeResponse, Verdict } from '../types/extension';

export const Interstitial: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [attemptId, setAttemptId] = useState('');
  const [loading, setLoading] = useState(true);
  const [verdictData, setVerdictData] = useState<AnalyzeResponse | null>(null);
  const [errorText, setErrorText] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url') || '';
    const attId = params.get('attemptId') || `att_${Date.now()}`;
    setTargetUrl(url);
    setAttemptId(attId);

    if (!url) {
      setErrorText('No destination URL provided.');
      setLoading(false);
      return;
    }

    // Request analysis from background
    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_URL',
        payload: { url, attemptId: attId, source: 'chrome_extension' },
      },
      (res) => {
        setLoading(false);
        if (!res || !res.success) {
          setErrorText(res?.error || 'Unable to connect to AEGIS verification engine.');
        } else {
          setVerdictData(res.data as AnalyzeResponse);
        }
      }
    );
  }, []);

  const handleReturnToSafety = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  };

  const handleProceedAtOwnRisk = () => {
    if (!targetUrl) return;

    // Record decision via background
    chrome.runtime.sendMessage({
      type: 'RECORD_DECISION',
      payload: { scan_id: verdictData?.scan_id, url: targetUrl, decision: 'proceed' },
    });

    // Register one-time approval so resumed navigation does not loop
    chrome.runtime.sendMessage(
      {
        type: 'REGISTER_APPROVAL',
        payload: { url: targetUrl, attemptId },
      },
      () => {
        window.location.href = targetUrl;
      }
    );
  };

  const verdict: Verdict = verdictData?.verdict || (errorText ? 'INSUFFICIENT_EVIDENCE' : 'SAFE');

  return (
    <div
      className="min-h-screen text-slate-900 flex flex-col items-center justify-center p-4 sm:p-6 font-sans bg-[#F8F9FA]"
      style={{
        backgroundImage: "url('/silky-wave.png')",
        backgroundSize: 'cover',
        backgroundPosition: 'center top',
        backgroundRepeat: 'no-repeat',
      }}
    >
      <div className="w-full max-w-xl bg-white/95 backdrop-blur-md border border-slate-200/90 rounded-2xl shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-200/80">
          <div className="flex items-center gap-3">
            <img src="/aegis-gothic-shield-emblem.png" alt="AEGIS Emblem" className="w-9 h-9 object-contain shrink-0" />
            <div>
              <div className="font-black text-sm tracking-widest text-black uppercase">AEGIS DEFENSE</div>
              <div className="text-[11px] text-slate-500 font-semibold tracking-wider uppercase">Security Navigation Guard</div>
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-slate-600 font-medium">
            <Lock className="w-3.5 h-3.5 text-slate-500" />
            <span>Active Protection</span>
          </div>
        </div>

        {/* Destination preview */}
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/90">
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">
            Destination URL
          </div>
          <p className="font-mono text-xs text-slate-900 font-medium break-all select-all">
            {targetUrl || 'Detecting target...'}
          </p>
        </div>

        {/* Loading */}
        {loading && (
          <div className="py-8 flex flex-col items-center justify-center text-slate-600 space-y-3">
            <Loader2 className="w-8 h-8 animate-spin text-black" />
            <div className="text-sm font-bold text-slate-900">Inspecting link with multi-engine detectors...</div>
            <p className="text-xs text-slate-500">Evaluating ML classifier, threat lists, and lookalike models</p>
          </div>
        )}

        {/* Critical Malicious Result */}
        {!loading && verdict === 'CRITICAL' && (
          <div className="p-5 rounded-xl bg-red-50 border border-red-200 text-red-900 space-y-3 shadow-xs">
            <div className="flex items-center gap-3 text-red-700">
              <ShieldAlert className="w-7 h-7 shrink-0" />
              <div>
                <h1 className="text-lg font-black text-red-950 leading-tight">Deceptive Threat Blocked</h1>
                <div className="text-xs text-red-700 font-bold uppercase tracking-wider">Action: BLOCK</div>
              </div>
            </div>
            <p className="text-xs text-red-800 leading-relaxed font-medium">
              {verdictData?.reason || 'This destination has been confirmed as a malicious phishing or credential theft site.'}
            </p>
            <div className="pt-1 text-[11px] text-red-700 font-semibold">
              Direct bypass is permanently disabled by AEGIS policy to protect against credential loss and malware.
            </div>
          </div>
        )}

        {/* Suspicious Result */}
        {!loading && verdict === 'SUSPICIOUS' && (
          <div className="p-5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 space-y-3 shadow-xs">
            <div className="flex items-center gap-3 text-amber-700">
              <AlertTriangle className="w-7 h-7 shrink-0" />
              <div>
                <h1 className="text-lg font-black text-amber-950 leading-tight">Caution: Suspicious Destination</h1>
                <div className="text-xs text-amber-700 font-bold uppercase tracking-wider">Action: WARN</div>
              </div>
            </div>
            <p className="text-xs text-amber-800 leading-relaxed font-medium">
              {verdictData?.reason || 'The available security signals indicate possible phishing, homoglyph deception, or unverified origin.'}
            </p>
            {verdictData?.domain_impersonation?.possible_match && (
              <div className="text-xs font-bold text-amber-900">
                Possible brand target: {verdictData.domain_impersonation.possible_match}
              </div>
            )}
          </div>
        )}

        {/* Insufficient Evidence / Error */}
        {!loading && (errorText || verdict === 'INSUFFICIENT_EVIDENCE') && (
          <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 text-slate-800 space-y-2">
            <h1 className="text-sm font-bold text-slate-900">Unable to Complete Full Verification</h1>
            <p className="text-xs text-slate-600 leading-relaxed">
              {errorText || verdictData?.reason || 'Security checks could not complete due to provider timeout or network unavailability.'}
            </p>
            <p className="text-[11px] text-amber-700 font-semibold">
              In accordance with conservative fail-safe policy, unverified links are not marked safe.
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-slate-200/80">
          <button
            type="button"
            onClick={handleReturnToSafety}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-black hover:bg-neutral-800 text-white text-xs font-bold transition-all shadow-md"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Safety</span>
          </button>

          {/* Suspicious: Require deliberate Proceed action */}
          {verdict === 'SUSPICIOUS' && (
            <button
              type="button"
              onClick={handleProceedAtOwnRisk}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold uppercase tracking-wider transition-colors shadow-xs"
            >
              <span>Proceed at Own Risk</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Unverified: Proceed with caution */}
          {(errorText || verdict === 'INSUFFICIENT_EVIDENCE') && (
            <button
              type="button"
              onClick={handleProceedAtOwnRisk}
              className="w-full sm:w-auto text-xs text-slate-600 hover:text-slate-900 font-medium underline"
            >
              Proceed to Destination
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
