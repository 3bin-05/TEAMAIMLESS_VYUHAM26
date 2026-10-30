import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Compass,
  Lock,
  EyeOff,
  CheckCircle2,
  ArrowRight,
  Info,
} from 'lucide-react';

export const CoveragePrivacyPage: React.FC = () => {
  return (
    <div className="flex-1 w-full max-w-4xl mx-auto px-4 sm:px-6 py-12">
      {/* Header Section */}
      <div className="mb-8">
        <div className="text-[11px] font-bold text-neutral-500 uppercase tracking-widest mb-1">
          ARCHITECTURE &amp; SECURITY POLICY
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-neutral-900 tracking-tight mb-2">
          Coverage &amp; Privacy Guarantee
        </h1>
        <p className="text-sm text-neutral-500">
          Comprehensive disclosure of browser interception boundaries, privacy principles, and zero-secret architecture.
        </p>
      </div>

      <div className="space-y-6">
        {/* Card 1: Navigation Coverage & Interception Boundaries */}
        <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] p-6 sm:p-7 space-y-5">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center shrink-0 text-neutral-800">
              <Compass className="w-6 h-6 text-neutral-800" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold text-neutral-900 uppercase tracking-wider mb-1">
                EXTENSION NAVIGATION COVERAGE &amp; BOUNDARIES
              </h2>
              <p className="text-xs text-neutral-500 leading-relaxed">
                Deterministic security boundary rules governed by Chrome Manifest V3 architectural capabilities.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            <div className="p-4 bg-neutral-50/80 border border-neutral-200/70 rounded-xl space-y-1.5">
              <div className="flex items-center gap-2 font-bold text-xs text-neutral-900">
                <CheckCircle2 className="w-4 h-4 text-black" />
                <span>Navigation Guard (In-Page Links)</span>
              </div>
              <p className="text-xs text-neutral-600 leading-relaxed font-normal">
                Intercepts standard HTML link clicks (<code className="bg-neutral-200/70 font-mono text-[11px] px-1.5 py-0.5 rounded text-neutral-800">&lt;a href&gt;</code>) within supported web pages, temporarily halting navigation while requesting server-side verdict.
              </p>
            </div>

            <div className="p-4 bg-neutral-50/80 border border-neutral-200/70 rounded-xl space-y-1.5">
              <div className="flex items-center gap-2 font-bold text-xs text-neutral-900">
                <CheckCircle2 className="w-4 h-4 text-black" />
                <span>Loop Prevention Mechanism</span>
              </div>
              <p className="text-xs text-neutral-600 leading-relaxed font-normal">
                When a link is declared Safe or approved by informed user override, a single-use 15-second approval token is consumed to prevent infinite intercept loops.
              </p>
            </div>

            <div className="p-4 bg-neutral-50/80 border border-neutral-200/70 rounded-xl space-y-1.5">
              <div className="flex items-center gap-2 font-bold text-xs text-neutral-900">
                <CheckCircle2 className="w-4 h-4 text-black" />
                <span>Google SearchGuard</span>
              </div>
              <p className="text-xs text-neutral-600 leading-relaxed font-normal">
                Automatically scans organic Google Search results in debounced batches and decorates links with real-time verification status badges.
              </p>
            </div>

            <div className="p-4 bg-neutral-50/80 border border-neutral-200/70 rounded-xl space-y-1.5">
              <div className="flex items-center gap-2 font-bold text-xs text-neutral-900">
                <CheckCircle2 className="w-4 h-4 text-black" />
                <span>Strict Policy Fail-Safe</span>
              </div>
              <p className="text-xs text-neutral-600 leading-relaxed font-normal">
                Links confirmed as CRITICAL threats are permanently blocked with proceed bypass disabled. Suspicious links require conscious user consent.
              </p>
            </div>
          </div>

          <div className="p-4 bg-neutral-50 border border-neutral-200/80 rounded-xl flex items-start gap-3 text-neutral-600 text-xs leading-relaxed">
            <Info className="w-4 h-4 text-neutral-800 shrink-0 mt-0.5" />
            <div>
              <strong className="text-neutral-900">Platform Boundaries:</strong> Under Chrome Manifest V3, arbitrary omnibox address-bar typed navigations cannot be paused synchronously before initial network packets transmit. AEGIS enforces link-level pre-navigation verification and interstitial defenses.
            </div>
          </div>
        </div>

        {/* Card 2: Zero Client Secrets Policy */}
        <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] p-6 sm:p-7 space-y-5">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center shrink-0 text-neutral-800">
              <Lock className="w-6 h-6 text-neutral-800" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold text-neutral-900 uppercase tracking-wider mb-1">
                ZERO CLIENT SECRETS ARCHITECTURE
              </h2>
              <p className="text-xs text-neutral-500 leading-relaxed">
                Cryptographic and operational segregation between browser clients and threat intelligence providers.
              </p>
            </div>
          </div>

          <div className="p-4 bg-neutral-50/90 border border-neutral-200/90 rounded-xl space-y-2 text-xs text-neutral-600 leading-relaxed">
            <p>
              In strict compliance with enterprise security specifications, AEGIS stores <strong className="text-neutral-900">zero third-party provider credentials</strong> (such as Google Safe Browsing keys, VirusTotal API tokens, or Anthropic Claude API keys) inside client-side JavaScript bundles, extension storage, or cookies.
            </p>
            <p>
              All external intelligence calls, reputation scoring, and heuristics are exclusively orchestrated on the backend server behind the FastAPI policy engine. Client components only communicate with configured AEGIS REST endpoints.
            </p>
          </div>
        </div>

        {/* Card 3: Privacy & Telemetry Minimization */}
        <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] p-6 sm:p-7 space-y-5">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-neutral-100 flex items-center justify-center shrink-0 text-neutral-800">
              <EyeOff className="w-6 h-6 text-neutral-800" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold text-neutral-900 uppercase tracking-wider mb-1">
                DATA PRIVACY &amp; TELEMETRY MINIMIZATION
              </h2>
              <p className="text-xs text-neutral-500 leading-relaxed">
                No session tracking, no background keylogging, and no browsing profile harvesting.
              </p>
            </div>
          </div>

          <div className="space-y-3 text-xs text-neutral-600 leading-relaxed">
            <div className="flex items-start gap-3">
              <div className="w-2 h-2 rounded-full bg-black shrink-0 mt-1.5" />
              <p>
                <strong className="text-neutral-900">Target URL Only:</strong> When inspecting links, only the destination URL and its caller domain context are transmitted for multi-engine verification.
              </p>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-2 h-2 rounded-full bg-black shrink-0 mt-1.5" />
              <p>
                <strong className="text-neutral-900">Zero Analytics Trackers:</strong> No third-party tracking pixels, marketing telemetry, or user fingerprinting libraries exist in the AEGIS codebase.
              </p>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-2 h-2 rounded-full bg-black shrink-0 mt-1.5" />
              <p>
                <strong className="text-neutral-900">Local Configuration Ownership:</strong> Backend API endpoints and user preferences remain stored solely in your local browser storage (<code className="bg-neutral-200/70 font-mono text-[11px] px-1.5 py-0.5 rounded text-neutral-800">localStorage</code> / <code className="bg-neutral-200/70 font-mono text-[11px] px-1.5 py-0.5 rounded text-neutral-800">chrome.storage.local</code>).
              </p>
            </div>
          </div>

          {/* Bottom Action Links */}
          <div className="pt-4 border-t border-neutral-100 flex flex-col sm:flex-row items-center justify-between gap-4">
            <Link
              to="/settings"
              className="inline-flex items-center gap-2 text-xs font-bold text-neutral-900 hover:text-black"
            >
              <span>Manage Backend API Configuration</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>

            <Link
              to="/"
              className="h-10 px-5 rounded-xl bg-neutral-950 hover:bg-black text-white text-xs font-bold flex items-center gap-2 shadow-xs transition-colors"
            >
              <Shield className="w-4 h-4 text-white" />
              <span>Launch Live URL Scanner</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
