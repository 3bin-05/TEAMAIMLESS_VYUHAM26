import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  HelpCircle,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  ArrowLeft,
  Sparkles,
  Building,
  History
} from 'lucide-react';
import type { Verdict, PolicyAction, AIExplanation } from '../../types/api';

interface VerdictCardProps {
  verdict: Verdict;
  action: PolicyAction;
  riskScore?: number | null;
  reason?: string;
  url: string;
  scanId?: string;
  timestamp?: string;
  aiExplanation?: AIExplanation;
  onReset?: () => void;
  onProceedAtOwnRisk?: () => void;
  isExtensionContext?: boolean;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({
  verdict: rawVerdict,
  action,
  reason,
  url,
  scanId,
  timestamp,
  aiExplanation,
  onReset,
  onProceedAtOwnRisk,
  isExtensionContext = false,
}) => {
  const [copied, setCopied] = useState(false);
  const [countdown, setCountdown] = useState<number>(3);
  const [redirectPaused, setRedirectPaused] = useState<boolean>(false);

  // Normalize verdict based on AI risk level or server verdict
  const effectiveRisk = (aiExplanation?.risk_level || '').toLowerCase();
  let normalizedVerdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'INCONCLUSIVE';

  if (effectiveRisk === 'malicious' || rawVerdict === 'MALICIOUS' || rawVerdict === 'CRITICAL') {
    normalizedVerdict = 'MALICIOUS';
  } else if (effectiveRisk === 'suspicious' || rawVerdict === 'SUSPICIOUS') {
    normalizedVerdict = 'SUSPICIOUS';
  } else if (effectiveRisk === 'safe' || rawVerdict === 'SAFE') {
    normalizedVerdict = 'SAFE';
  } else {
    normalizedVerdict = 'INCONCLUSIVE';
  }

  // Auto-redirect timer for SAFE results (Req 15.7.A)
  useEffect(() => {
    if (normalizedVerdict !== 'SAFE' || redirectPaused) return;

    if (countdown <= 0) {
      // Set session authorization key to prevent redirect loops
      try {
        sessionStorage.setItem(`aegis_authorized_${encodeURIComponent(url)}`, 'true');
      } catch {
        // storage disabled or sandboxed
      }
      window.location.href = url;
      return;
    }

    const timer = setInterval(() => {
      setCountdown((prev) => prev - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [normalizedVerdict, countdown, redirectPaused, url]);

  const handleCopy = () => {
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGoBack = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else if (onReset) {
      onReset();
    } else {
      window.location.href = '/';
    }
  };

  const handleAuthorizeProceed = () => {
    if (onProceedAtOwnRisk) {
      onProceedAtOwnRisk();
    } else {
      // Temporary single-navigation authorization
      try {
        sessionStorage.setItem(`aegis_authorized_${encodeURIComponent(url)}`, 'true');
      } catch {
        // ignore
      }
      window.location.href = url;
    }
  };

  // Curated theme styles per Phase 15
  const getVerdictTheme = () => {
    switch (normalizedVerdict) {
      case 'SAFE':
        return {
          title: 'SAFE',
          headline: 'Verified Safe by AEGIS AI',
          icon: CheckCircle2,
          iconBg: 'bg-emerald-600 text-white shadow-emerald-200 shadow-md',
          containerClass: 'bg-gradient-to-b from-emerald-50/80 to-white border-emerald-200/80 text-emerald-950',
          pillBg: 'bg-emerald-100 text-emerald-800 border-emerald-300',
          summaryFallback:
            'AEGIS AI has evaluated all available cybersecurity evidence and found no significant indicators of phishing or malicious activity.',
          defaultReasons: [
            'The domain has an established registration history.',
            'Available evidence supports its association with the claimed organization.',
            'No significant threat intelligence matches were identified.',
            'No major suspicious anomalies were detected.'
          ]
        };
      case 'SUSPICIOUS':
        return {
          title: 'SUSPICIOUS',
          headline: 'Suspicious Activity Detected by AEGIS AI',
          icon: AlertTriangle,
          iconBg: 'bg-amber-600 text-white shadow-amber-200 shadow-md',
          containerClass: 'bg-gradient-to-b from-amber-50/80 to-white border-amber-200/80 text-amber-950',
          pillBg: 'bg-amber-100 text-amber-800 border-amber-300',
          summaryFallback:
            'AEGIS AI has identified suspicious indicators that suggest potential phishing, deceptive impersonation, or unverified domain credibility.',
          defaultReasons: [
            'The domain has limited verifiable registration history.',
            'Its claimed organizational identity could not be independently established.',
            'Technical anomaly analysis identified unusual URL characteristics.',
            'Available threat intelligence provides conflicting or unverified evidence.'
          ]
        };
      case 'MALICIOUS':
        return {
          title: 'MALICIOUS',
          headline: 'Malicious Threat Detected by AEGIS AI',
          icon: ShieldAlert,
          iconBg: 'bg-red-600 text-white shadow-red-200 shadow-md',
          containerClass: 'bg-gradient-to-b from-red-50/90 to-white border-red-200/90 text-red-950',
          pillBg: 'bg-red-100 text-red-800 border-red-300',
          summaryFallback:
            'AEGIS AI has determined that this website presents active malicious risks, phishing signatures, or deceptive brand impersonation.',
          defaultReasons: [
            'The destination has been associated with confirmed phishing activity.',
            'Multiple threat intelligence findings support a malicious classification.',
            'The website appears to impersonate a legitimate organization or brand.',
            'Technical anomalies support the active threat assessment.'
          ]
        };
      case 'INCONCLUSIVE':
      default:
        return {
          title: 'INCONCLUSIVE',
          headline: 'Verification Failed / Inconclusive Evidence',
          icon: HelpCircle,
          iconBg: 'bg-slate-700 text-white shadow-slate-200 shadow-md',
          containerClass: 'bg-gradient-to-b from-slate-50 to-white border-slate-300 text-slate-900',
          pillBg: 'bg-slate-200 text-slate-800 border-slate-300',
          summaryFallback:
            'AEGIS AI could not gather sufficient verifiable historical or threat intelligence data to confirm safety. Conservative security failure policy applies.',
          defaultReasons: [
            'Essential domain registration information was unavailable or obscured.',
            'Threat intelligence databases returned inconclusive coverage for this host.',
            'Safe verification could not be completed within the analysis deadline.'
          ]
        };
    }
  };

  const theme = getVerdictTheme();
  const Icon = theme.icon;

  // AI-generated summary paragraph (Req 15.7 / 15.8)
  const aiSummary = aiExplanation?.summary || reason || theme.summaryFallback;

  // AI Reasons list
  const aiReasons = aiExplanation?.reasons && aiExplanation.reasons.length > 0
    ? aiExplanation.reasons
    : null;

  return (
    <div
      className={`w-full max-w-3xl mx-auto rounded-3xl border p-6 sm:p-9 shadow-sm transition-all ${theme.containerClass}`}
      role="region"
      aria-label={`AEGIS AI Security Verdict: ${theme.title}`}
    >
      {/* 1. Large Risk Indicator & Risk Classification */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-5 pb-6 border-b border-black/5">
        <div className="flex items-center gap-4">
          <div className={`w-16 h-16 rounded-2xl flex items-center justify-center shrink-0 ${theme.iconBg}`}>
            <Icon className="w-9 h-9 stroke-[2.2]" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`px-3 py-1 rounded-full text-xs font-black tracking-widest uppercase border ${theme.pillBg}`}>
                {theme.title}
              </span>
              {action && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-slate-100 text-slate-700 border border-slate-200">
                  Action: {action}
                </span>
              )}
              {isExtensionContext && (
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-blue-50 text-blue-700 border border-blue-200">
                  Extension Gateway
                </span>
              )}
              <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                <Sparkles className="w-3.5 h-3.5 text-blue-600" />
                <span>Ollama AI Threat Analyst Verdict</span>
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight mt-1.5 text-slate-900 font-sans">
              {theme.title}
            </h1>
          </div>
        </div>

        {/* Safe Auto-redirect Banner (Req 15.7.A) */}
        {normalizedVerdict === 'SAFE' && !redirectPaused && (
          <div className="flex items-center gap-3 bg-emerald-100/80 border border-emerald-300/80 px-4 py-2.5 rounded-xl text-xs font-semibold text-emerald-900">
            <span>Redirecting in <strong>{countdown}s</strong>...</span>
            <button
              type="button"
              onClick={() => setRedirectPaused(true)}
              className="text-[11px] underline hover:text-emerald-950 font-bold"
            >
              Pause
            </button>
          </div>
        )}
      </div>

      {/* 2. Target URL */}
      <div className="mt-5 p-3.5 bg-white/90 rounded-xl border border-slate-200/80 shadow-xs flex items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-bold text-slate-500 uppercase tracking-wider shrink-0 text-[10px]">
            Target URL:
          </span>
          <span className="font-mono text-slate-800 truncate select-all font-medium">
            {url}
          </span>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 text-slate-600 hover:text-slate-900 font-medium shrink-0 transition-colors"
          title="Copy URL"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      {/* 3. AI-Generated Summary (Req 15.7 / 15.8) */}
      <div className="mt-6 p-5 rounded-2xl bg-white/95 border border-slate-200/90 shadow-xs">
        <div className="flex items-center gap-1.5 text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          <Sparkles className="w-4 h-4 text-blue-600" />
          <span>AI Analysis Summary</span>
        </div>
        <p className="text-sm sm:text-base text-slate-900 font-medium leading-relaxed">
          &ldquo;{aiSummary}&rdquo;
        </p>
      </div>

      {/* 4. AI-Generated Bullet-Point Explanations (Req 15.7 / 15.8) */}
      <div className="mt-6">
        <h2 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-3">
          Key Reasons &amp; Supporting Evidence:
        </h2>

        <div className="space-y-2.5">
          {aiReasons ? (
            aiReasons.map((r, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-white/90 border border-slate-200/80 shadow-xs flex items-start gap-3 text-xs"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-slate-900 mt-1.5 shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <strong className="text-slate-900 font-semibold">{r.title}</strong>
                    {r.source && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                        {r.source}
                      </span>
                    )}
                    {r.severity && (
                      <span
                        className={`text-[10px] font-bold uppercase px-1.5 py-0.2 rounded ${
                          r.severity === 'high' || r.severity === 'critical'
                            ? 'bg-red-100 text-red-700'
                            : r.severity === 'medium'
                            ? 'bg-amber-100 text-amber-700'
                            : 'bg-emerald-100 text-emerald-700'
                        }`}
                      >
                        {r.severity}
                      </span>
                    )}
                  </div>
                  <p className="text-slate-700 mt-1 leading-relaxed">{r.explanation}</p>
                </div>
              </div>
            ))
          ) : (
            theme.defaultReasons.map((reasonText, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-white/90 border border-slate-200/80 shadow-xs flex items-start gap-3 text-xs"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-slate-900 mt-1.5 shrink-0" />
                <p className="text-slate-800 leading-relaxed font-medium">{reasonText}</p>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 5. Domain History & Organization Legitimacy Summary Cards */}
      {(aiExplanation?.domain_history || aiExplanation?.organization_verification) && (
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          {aiExplanation.domain_history && (
            <div className="p-3.5 rounded-xl bg-white/80 border border-slate-200/70">
              <div className="flex items-center gap-1.5 text-slate-600 font-semibold mb-1">
                <History className="w-3.5 h-3.5" />
                <span>Domain History:</span>
                <span className="font-mono text-slate-900 uppercase font-bold text-[10px] bg-slate-100 px-1.5 py-0.5 rounded">
                  {aiExplanation.domain_history.status || 'Verified'}
                </span>
              </div>
              <p className="text-slate-700 text-[11px] leading-relaxed">
                {aiExplanation.domain_history.explanation}
              </p>
            </div>
          )}

          {aiExplanation.organization_verification && (
            <div className="p-3.5 rounded-xl bg-white/80 border border-slate-200/70">
              <div className="flex items-center gap-1.5 text-slate-600 font-semibold mb-1">
                <Building className="w-3.5 h-3.5" />
                <span>Organization Identity:</span>
                <span className="font-mono text-slate-900 uppercase font-bold text-[10px] bg-slate-100 px-1.5 py-0.5 rounded">
                  {aiExplanation.organization_verification.status || 'Verified'}
                </span>
              </div>
              <p className="text-slate-700 text-[11px] leading-relaxed">
                {aiExplanation.organization_verification.explanation}
              </p>
            </div>
          )}
        </div>
      )}

      {/* 6. Navigation Actions strictly per Section 15.7 */}
      <div className="mt-8 pt-6 border-t border-black/5 flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* SAFE Actions */}
        {normalizedVerdict === 'SAFE' && (
          <div className="flex items-center gap-3 w-full sm:w-auto">
            <a
              href={url}
              onClick={() => {
                try {
                  sessionStorage.setItem(`aegis_authorized_${encodeURIComponent(url)}`, 'true');
                } catch {}
              }}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-bold shadow-md shadow-emerald-200 transition-all hover:shadow-lg"
            >
              <span>Continue to Website</span>
              <ExternalLink className="w-4 h-4" />
            </a>

            {onReset && (
              <button
                type="button"
                onClick={onReset}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 text-sm font-semibold transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                <span>New Scan</span>
              </button>
            )}
          </div>
        )}

        {/* SUSPICIOUS Actions */}
        {normalizedVerdict === 'SUSPICIOUS' && (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 w-full">
            <button
              type="button"
              onClick={handleGoBack}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-slate-900 hover:bg-black text-white text-sm font-bold shadow-md transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Go Back to Safety</span>
            </button>

            <button
              type="button"
              onClick={handleAuthorizeProceed}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-amber-50 hover:bg-amber-100 border border-amber-300 text-amber-900 text-xs font-bold uppercase tracking-wider transition-colors"
            >
              <span>Proceed at Your Own Risk</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* MALICIOUS Actions (DO NOT PROVIDE PROCEED ANYWAY - Req 15.7.C) */}
        {normalizedVerdict === 'MALICIOUS' && (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 w-full">
            <button
              type="button"
              onClick={handleGoBack}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-red-600 hover:bg-red-700 text-white text-sm font-bold shadow-md shadow-red-200 transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Go Back to Safety</span>
            </button>

            <span className="text-xs font-semibold text-red-700 bg-red-100 px-3 py-1.5 rounded-lg border border-red-200">
              Malicious Navigation Blocked by AEGIS
            </span>
          </div>
        )}

        {/* INCONCLUSIVE Actions (Req 15.7.D) */}
        {normalizedVerdict === 'INCONCLUSIVE' && (
          <div className="flex items-center gap-3 w-full sm:w-auto">
            <button
              type="button"
              onClick={handleGoBack}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-sm font-bold shadow-sm transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Go Back to Safety</span>
            </button>

            {onReset && (
              <button
                type="button"
                onClick={onReset}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 text-sm font-semibold transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Retry Scan</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* Metadata bar */}
      {(scanId || timestamp) && (
        <div className="mt-5 pt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400 border-t border-black/5">
          {scanId && <span>Scan ID: {scanId}</span>}
          {timestamp && <span>Analyzed: {new Date(timestamp).toLocaleString()}</span>}
        </div>
      )}
    </div>
  );
};
