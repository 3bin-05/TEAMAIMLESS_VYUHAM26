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
  Activity,
  Cpu,
  Globe,
  ShieldCheck,
  SearchCheck,
} from 'lucide-react';
import type {
  AnalyzeChecks,
  DomainShieldCheck,
  AIExplanation,
} from '../../types/api';

interface ThreatReportProps {
  checks?: AnalyzeChecks;
  domainImpersonation?: DomainShieldCheck;
  aiExplanation?: AIExplanation | null;
  normalizedUrl?: string;
}

export const ThreatReport: React.FC<ThreatReportProps> = ({
  checks,
  domainImpersonation: rootDomainImpersonation,
  aiExplanation,
  normalizedUrl,
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  // Extract DomainShield from root or checks
  const dsCheck = rootDomainImpersonation || checks?.domain_shield;
  const isLookalike =
    dsCheck?.is_lookalike ||
    dsCheck?.impersonation_detected ||
    dsCheck?.details?.impersonation_detected ||
    false;

  const matchedBrand =
    dsCheck?.matched_brand ||
    dsCheck?.details?.matched_brand ||
    dsCheck?.possible_match ||
    null;

  const officialDomain =
    dsCheck?.official_domain ||
    dsCheck?.official_target_domain ||
    dsCheck?.details?.official_domain ||
    dsCheck?.details?.official_target_domain ||
    null;

  const similarityScore =
    dsCheck?.similarity_score ??
    dsCheck?.details?.similarity_score ??
    (dsCheck?.similarity !== undefined && dsCheck.similarity !== null
      ? dsCheck.similarity > 1
        ? dsCheck.similarity
        : dsCheck.similarity * 100
      : null);

  const techniques =
    dsCheck?.details?.techniques_triggered ||
    dsCheck?.detection_techniques ||
    [];

  const dsEvidence =
    dsCheck?.details?.supporting_evidence ||
    dsCheck?.supporting_evidence ||
    [];

  // Extract ML Check
  const ml = checks?.ml;
  const mlPrediction = ml?.prediction || ml?.details?.prediction;
  const mlConfidence =
    ml?.confidence ??
    ml?.phishing_probability ??
    ml?.details?.confidence ??
    ml?.details?.phishing_probability;
  const mlModel = ml?.model_name || ml?.details?.model_name || 'PhishOFE-URL-Classifier';
  const mlFeatures = ml?.features_used || ml?.details?.features_used || 11;

  // Extract Google Safe Browsing
  const gsb = checks?.google_safe_browsing;
  const gsbDetected = gsb?.threat_detected ?? gsb?.details?.threat_detected;

  // Extract RDAP
  const rdap = checks?.rdap;
  const rdapDomain = rdap?.domain || rdap?.details?.domain;
  const rdapRegistered = rdap?.registered ?? rdap?.details?.registered;
  const rdapRegistrar = rdap?.registrar || rdap?.details?.registrar;
  const rdapAgeDays = rdap?.domain_age_days ?? rdap?.details?.domain_age_days;
  const rdapCreation = rdap?.creation_date || rdap?.registration_date || rdap?.details?.creation_date;

  // Extract VirusTotal
  const vt = checks?.virustotal;
  const vtMalicious = vt?.malicious ?? vt?.details?.malicious;
  const vtReason = vt?.reason || vt?.details?.reason;

  // AI anomalies & links
  const anomalies = aiExplanation?.anomalies || [];
  const similarSites = aiExplanation?.similar_sites || [];
  const domainHistory = aiExplanation?.domain_history;
  const orgVerification = aiExplanation?.organization_verification;

  // Format domain age helper
  const formatDomainAge = (days: number | null | undefined): string => {
    if (days === null || days === undefined) return 'Unknown / Unverified';
    if (days === 0) return 'Registered Today';
    if (days < 30) return `${days} days (Newly Registered)`;
    if (days < 365) return `${Math.floor(days / 30)} months (${days} days)`;
    const years = (days / 365).toFixed(1);
    return `${years} years (${days.toLocaleString()} days)`;
  };

  return (
    <div className="w-full max-w-3xl mx-auto mt-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-blue-600" />
          <h2 className="text-sm font-bold text-slate-900 tracking-tight">
            Security Intelligence &amp; Multi-Engine Threat Dossier
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
          Analyzed Host: <span className="text-slate-700 font-semibold">{normalizedUrl}</span>
        </div>
      )}

      {isExpanded && (
        <div className="space-y-4 animate-fadeIn">
          {/* 1. Brand Impersonation Alert (DomainShield) */}
          {isLookalike && matchedBrand ? (
            <div className="p-4 rounded-2xl border border-red-300 bg-red-50/90 shadow-xs">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-xs font-bold text-red-950 uppercase tracking-wider">
                      Brand Impersonation Threat
                    </h3>
                    {similarityScore !== null && (
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-red-200/90 text-red-900 rounded">
                        {Math.round(similarityScore)}% Lookalike Match
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-red-900 mt-1">
                    This domain exhibits deceptive lookalike characteristics imitating{' '}
                    <strong className="font-bold">{matchedBrand}</strong>.
                  </p>

                  {officialDomain && (
                    <div className="mt-3 inline-flex items-center gap-2 p-2 rounded-xl bg-white border border-red-200 text-xs">
                      <span className="text-slate-600 font-medium">Legitimate Destination:</span>
                      <a
                        href={`https://${officialDomain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono font-bold text-blue-700 hover:text-blue-900 hover:underline"
                      >
                        <span>{officialDomain}</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  )}

                  {techniques.length > 0 && (
                    <div className="mt-2 text-[10px] text-red-700 font-mono">
                      Detection Technique: {techniques.join(', ')}
                    </div>
                  )}

                  {dsEvidence.length > 0 && (
                    <div className="mt-1.5 text-[11px] text-red-800 font-mono">
                      {dsEvidence[0]}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : dsCheck ? (
            <div className="p-3.5 rounded-2xl bg-white border border-emerald-200/80 shadow-xs flex items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                <div>
                  <span className="font-bold text-slate-800">DomainShield Brand Verification:</span>{' '}
                  <span className="text-slate-600">No brand impersonation, homoglyphs, or lookalikes detected.</span>
                </div>
              </div>
              <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded">
                Verified Clean
              </span>
            </div>
          ) : null}

          {/* 2. Core Telemetry Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {/* ML Classification Card */}
            {ml && (
              <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 font-bold text-slate-800">
                    <Cpu className="w-4 h-4 text-indigo-600" />
                    <span>Neural ML Classifier</span>
                  </div>
                  {mlPrediction && (
                    <span
                      className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                        mlPrediction === 'phishing'
                          ? 'bg-red-100 text-red-800 border border-red-200'
                          : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                      }`}
                    >
                      {mlPrediction}
                    </span>
                  )}
                </div>

                <div className="space-y-1.5 text-slate-600">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Phishing Probability:</span>
                    <span className="font-mono font-bold text-slate-800">
                      {mlConfidence !== undefined ? `${(mlConfidence * 100).toFixed(1)}%` : 'Evaluated'}
                    </span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Model Engine:</span>
                    <span className="font-mono text-slate-700">{mlModel}</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Analyzed Features:</span>
                    <span className="font-mono text-slate-700">{mlFeatures} URL heuristics</span>
                  </div>
                </div>
              </div>
            )}

            {/* Google Safe Browsing Card */}
            {gsb && (
              <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 font-bold text-slate-800">
                    <SearchCheck className="w-4 h-4 text-blue-600" />
                    <span>Google Safe Browsing</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                      gsbDetected
                        ? 'bg-red-100 text-red-800 border border-red-200'
                        : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                    }`}
                  >
                    {gsbDetected ? 'Threat Listed' : 'Clean'}
                  </span>
                </div>

                <div className="space-y-1.5 text-slate-600">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Threat Status:</span>
                    <span className="font-medium text-slate-800">
                      {gsbDetected ? 'Known malicious host detected' : 'Zero threat matches detected'}
                    </span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Registry Match:</span>
                    <span className="font-mono text-slate-700">
                      {gsb.details?.match_count ?? (gsbDetected ? 1 : 0)} entries
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* RDAP & Domain Intelligence */}
            {rdap && (
              <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 font-bold text-slate-800">
                    <Globe className="w-4 h-4 text-cyan-600" />
                    <span>RDAP Domain Registry</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                      rdapRegistered === false
                        ? 'bg-amber-100 text-amber-800 border border-amber-200'
                        : 'bg-slate-100 text-slate-800 border border-slate-200'
                    }`}
                  >
                    {rdapRegistered === false ? 'Unregistered' : 'Registered'}
                  </span>
                </div>

                <div className="space-y-1.5 text-slate-600">
                  {rdapDomain && (
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500">Registry Host:</span>
                      <span className="font-mono text-slate-700">{rdapDomain}</span>
                    </div>
                  )}
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-500">Domain Age:</span>
                    <span className="font-mono font-semibold text-slate-800">
                      {formatDomainAge(rdapAgeDays)}
                    </span>
                  </div>
                  {rdapRegistrar && (
                    <div className="flex justify-between text-[11px] truncate">
                      <span className="text-slate-500 shrink-0 mr-2">Registrar:</span>
                      <span className="font-mono text-slate-700 truncate" title={rdapRegistrar}>
                        {rdapRegistrar}
                      </span>
                    </div>
                  )}
                  {rdapCreation && (
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500">Registered On:</span>
                      <span className="font-mono text-slate-700">
                        {new Date(rdapCreation).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* VirusTotal & Threat Intelligence */}
            {vt && (
              <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 font-bold text-slate-800">
                    <Activity className="w-4 h-4 text-emerald-600" />
                    <span>VirusTotal Reputation</span>
                  </div>
                  <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                    {vt.status}
                  </span>
                </div>

                <div className="space-y-1.5 text-slate-600">
                  {vtMalicious !== undefined && vtMalicious !== null ? (
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500">Malicious Flags:</span>
                      <span className={`font-mono font-bold ${vtMalicious > 0 ? 'text-red-700' : 'text-emerald-700'}`}>
                        {vtMalicious} engines flagged
                      </span>
                    </div>
                  ) : vtReason ? (
                    <p className="text-[11px] text-slate-500 leading-tight">
                      {vtReason}
                    </p>
                  ) : (
                    <p className="text-[11px] text-slate-500">
                      Multi-engine reputation check completed.
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 3. Similar Legitimate Sites Suggested by AI */}
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

          {/* 4. Technical Anomalies Explained */}
          {anomalies.length > 0 && (
            <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-xs">
              <div className="flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-slate-600" />
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Technical Structural Anomalies
                </h3>
              </div>

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
            </div>
          )}

          {/* 5. Domain History & Organization Assessment */}
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

