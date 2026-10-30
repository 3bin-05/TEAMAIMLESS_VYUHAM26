import React, { useState } from 'react';
import {
  Sparkles,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  ExternalLink,
  Info,
  Calendar,
  Building,
  Activity
} from 'lucide-react';
import type {
  AnalyzeChecks,
  DomainShieldCheck,
  AIExplanation
} from '../../types/api';

interface ThreatReportProps {
  checks?: AnalyzeChecks;
  domainImpersonation?: DomainShieldCheck;
  aiExplanation?: AIExplanation;
  normalizedUrl?: string;
}

export const ThreatReport: React.FC<ThreatReportProps> = ({
  domainImpersonation,
  aiExplanation,
  normalizedUrl,
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  const anomalies = aiExplanation?.anomalies || [];
  const similarSites = aiExplanation?.similar_sites || [];
  const domainHistory = aiExplanation?.domain_history;
  const orgVerification = aiExplanation?.organization_verification;

  return (
    <div className="w-full max-w-3xl mx-auto mt-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-blue-600" />
          <h2 className="text-sm font-bold text-slate-900 tracking-tight">
            AI Threat Intelligence &amp; Anomaly Dossier
          </h2>
        </div>
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-xs font-semibold text-slate-500 hover:text-slate-800 flex items-center gap-1 transition-colors"
        >
          <span>{isExpanded ? 'Collapse' : 'Expand'}</span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {normalizedUrl && (
        <div className="text-[11px] font-mono text-slate-500 px-1 truncate">
          Target: <span className="text-slate-700 font-semibold">{normalizedUrl}</span>
        </div>
      )}

      {isExpanded && (
        <div className="space-y-4 animate-fadeIn">
          {/* 1. Brand Impersonation Alert & Official Destination (Req 15.1.B & 15.7) */}
          {domainImpersonation?.is_lookalike && domainImpersonation.possible_match && (
            <div className="p-4 rounded-2xl border border-amber-300 bg-amber-50/80 shadow-xs">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs font-bold text-amber-950 uppercase tracking-wider">
                      Brand Impersonation Alert
                    </h3>
                    {domainImpersonation.similarity !== null && domainImpersonation.similarity !== undefined && (
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-amber-200/90 text-amber-900 rounded">
                        {(domainImpersonation.similarity * 100).toFixed(0)}% Match
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-amber-900 mt-1">
                    This website exhibits lookalike characteristics imitating{' '}
                    <strong className="font-bold">{domainImpersonation.possible_match}</strong>.
                  </p>

                  {domainImpersonation.official_domain && (
                    <div className="mt-3 inline-flex items-center gap-2 p-2 rounded-xl bg-white border border-amber-300 text-xs">
                      <span className="text-slate-600 font-medium">Official Verified Domain:</span>
                      <a
                        href={`https://${domainImpersonation.official_domain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono font-bold text-blue-700 hover:text-blue-900 hover:underline"
                      >
                        <span>{domainImpersonation.official_domain}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 2. Similar Legitimate Sites Suggested by AI */}
          {similarSites.length > 0 && (
            <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
              <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
                Legitimate Alternative Destinations
              </h3>
              <div className="flex flex-wrap gap-2">
                {similarSites.map((site, idx) => (
                  <a
                    key={idx}
                    href={`https://${site}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-blue-700 hover:bg-blue-50 transition-colors"
                  >
                    <span>{site}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* 3. Technical Anomalies Explained in Plain English (Req 15.4) */}
          <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="w-4 h-4 text-slate-600" />
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Technical Structural Anomalies
              </h3>
            </div>

            {anomalies.length > 0 ? (
              <div className="space-y-2">
                {anomalies.map((anom, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-50 border border-slate-200/60 text-xs flex items-start gap-3"
                  >
                    <Info className="w-4 h-4 text-slate-500 mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <strong className="text-slate-900 font-semibold">{anom.title}</strong>
                        {anom.source && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-200/70 text-slate-600">
                            {anom.source}
                          </span>
                        )}
                      </div>
                      <p className="text-slate-700 mt-0.5 leading-relaxed">{anom.explanation}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">
                No technical structural anomalies (abnormal subdomain depth, lookalike hyphens, or unencrypted credential forms) were identified.
              </p>
            )}
          </div>

          {/* 4. Domain & Identity Assessment Summary */}
          {(domainHistory || orgVerification) && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              {domainHistory && (
                <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                  <div className="flex items-center gap-2 text-slate-700 font-bold mb-1.5">
                    <Calendar className="w-4 h-4 text-slate-500" />
                    <span>Domain History Credibility</span>
                  </div>
                  <p className="text-slate-600 leading-relaxed text-[11px]">
                    {domainHistory.explanation}
                  </p>
                </div>
              )}

              {orgVerification && (
                <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                  <div className="flex items-center gap-2 text-slate-700 font-bold mb-1.5">
                    <Building className="w-4 h-4 text-slate-500" />
                    <span>Organizational Legitimacy</span>
                  </div>
                  <p className="text-slate-600 leading-relaxed text-[11px]">
                    {orgVerification.explanation}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
