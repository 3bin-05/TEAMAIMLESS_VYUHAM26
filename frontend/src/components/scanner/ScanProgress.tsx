import React, { useState } from 'react';
import { Loader2, CheckCircle2, AlertTriangle, XCircle, Clock, Shield, Globe, Cpu, Sparkles, ChevronDown, ChevronUp } from 'lucide-react';
import type { ProviderStatus } from '../../types/api';

interface ProviderRowItem {
  id: string;
  name: string;
  description: string;
  icon: React.ElementType;
  status: ProviderStatus;
}

interface ScanProgressProps {
  url: string;
  providerStatuses?: Record<string, ProviderStatus>;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({ url, providerStatuses = {} }) => {
  const [showFullUrl, setShowFullUrl] = useState(false);

  const defaultProviders: ProviderRowItem[] = [
    {
      id: 'ml',
      name: 'Phishing ML Classifier',
      description: 'Lexical, statistical, and structural feature inference',
      icon: Cpu,
      status: providerStatuses.ml || 'pending',
    },
    {
      id: 'google_safe_browsing',
      name: 'Google Safe Browsing',
      description: 'Known threat lists & malware feeds',
      icon: Shield,
      status: providerStatuses.google_safe_browsing || 'pending',
    },
    {
      id: 'virustotal',
      name: 'VirusTotal Intelligence',
      description: 'Multi-engine antivirus & reputation aggregation',
      icon: Globe,
      status: providerStatuses.virustotal || 'pending',
    },
    {
      id: 'rdap',
      name: 'RDAP Domain Intelligence',
      description: 'Domain age, registrar validation, and whois signals',
      icon: Globe,
      status: providerStatuses.rdap || 'pending',
    },
    {
      id: 'domain_impersonation',
      name: 'DomainShield Brand Protection',
      description: 'Homoglyph, typosquatting & impersonation detection',
      icon: Shield,
      status: providerStatuses.domain_impersonation || 'pending',
    },
    {
      id: 'ai_explanation',
      name: 'AI Advisory Synthesis',
      description: 'Contextual risk assessment & reasoning explanation',
      icon: Sparkles,
      status: providerStatuses.ai_explanation || 'pending',
    },
  ];

  const getStatusBadge = (status: ProviderStatus) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Completed</span>
          </span>
        );
      case 'no_match':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-50 text-slate-600 border border-slate-200">
            <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
            <span>Clean / No Threat</span>
          </span>
        );
      case 'unavailable':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Unavailable</span>
          </span>
        );
      case 'timeout':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
            <Clock className="w-3.5 h-3.5" />
            <span>Timed out</span>
          </span>
        );
      case 'error':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">
            <XCircle className="w-3.5 h-3.5" />
            <span>Check failed</span>
          </span>
        );
      case 'pending':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Analyzing</span>
          </span>
        );
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto bg-white rounded-xl border border-slate-200 shadow-sm p-6 sm:p-8">
      {/* Header */}
      <div className="flex items-center justify-between pb-5 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 leading-tight">Analyzing Destination URL</h2>
            <p className="text-xs text-slate-500">Querying backend policy engine & verification pipelines</p>
          </div>
        </div>
      </div>

      {/* Target URL safe display */}
      <div className="my-5 p-3.5 bg-slate-50 rounded-lg border border-slate-200">
        <div className="flex items-center justify-between gap-2 text-xs text-slate-500 mb-1">
          <span className="font-semibold uppercase tracking-wider">Target Resource</span>
          <button
            type="button"
            onClick={() => setShowFullUrl(!showFullUrl)}
            className="flex items-center gap-1 text-blue-600 hover:text-blue-800 font-medium"
          >
            <span>{showFullUrl ? 'Truncate' : 'Show full URL'}</span>
            {showFullUrl ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
        <p
          className={`font-mono text-xs text-slate-800 break-all select-all ${
            showFullUrl ? '' : 'truncate'
          }`}
          title={url}
        >
          {url}
        </p>
      </div>

      {/* Provider Status Rows */}
      <div className="space-y-3">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
          Detection Pipelines
        </div>

        {defaultProviders.map((provider) => {
          const Icon = provider.icon;
          return (
            <div
              key={provider.id}
              className="flex items-center justify-between p-3 rounded-lg border border-slate-100 bg-white hover:bg-slate-50/50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-slate-50 text-slate-600">
                  <Icon className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-medium text-slate-800">{provider.name}</div>
                  <div className="text-xs text-slate-500">{provider.description}</div>
                </div>
              </div>
              <div>{getStatusBadge(provider.status)}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
