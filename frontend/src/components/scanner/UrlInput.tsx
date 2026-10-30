import React, { useState } from 'react';
import { Search, Loader2, ArrowRight, AlertCircle, Link2, Lock } from 'lucide-react';

interface UrlInputProps {
  onScan: (url: string) => void;
  isLoading: boolean;
}

export const UrlInput: React.FC<UrlInputProps> = ({ onScan, isLoading }) => {
  const [inputUrl, setInputUrl] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const validateUrl = (raw: string): { valid: boolean; normalized?: string; error?: string } => {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter a URL to check.' };
    }

    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { valid: false, error: 'Only HTTP and HTTPS URLs are supported for scanning.' };
      }
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        return { valid: false, error: 'Please enter a valid domain name (e.g. https://example.com).' };
      }
      return { valid: true, normalized: trimmed };
    } catch {
      // Check if user forgot protocol like "example.com"
      if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(trimmed)) {
        return { valid: true, normalized: `https://${trimmed}` };
      }
      return { valid: false, error: 'Malformed URL format. Please include a valid web address.' };
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isLoading) return;

    const { valid, normalized, error } = validateUrl(inputUrl);
    if (!valid || !normalized) {
      setValidationError(error || 'Invalid URL');
      return;
    }

    setValidationError(null);
    onScan(normalized);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInputUrl(e.target.value);
    if (validationError) {
      setValidationError(null);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div
          className={`flex items-center gap-2 rounded-2xl bg-white border shadow-xl shadow-black/[0.04] p-2 transition-all duration-200 ${
            validationError
              ? 'border-red-400 ring-2 ring-red-100'
              : 'border-slate-200/90 focus-within:border-black focus-within:ring-4 focus-within:ring-black/5'
          }`}
        >
          <div className="w-10 h-10 rounded-xl bg-neutral-100/90 border border-neutral-200/80 flex items-center justify-center shrink-0 ml-1 text-neutral-700 select-none">
            <Link2 className="w-4 h-4 text-neutral-700" />
          </div>

          <input
            id="url-scan-input"
            type="text"
            value={inputUrl}
            onChange={handleChange}
            placeholder="Enter a URL to analyze..."
            disabled={isLoading}
            aria-label="URL to inspect for phishing and malicious threats"
            aria-invalid={!!validationError}
            aria-describedby={validationError ? 'url-input-error' : undefined}
            className="w-full py-2.5 px-3 text-sm text-slate-900 placeholder:text-slate-400 bg-transparent focus:outline-none disabled:opacity-50"
            autoComplete="off"
            autoCorrect="off"
            spellCheck="false"
          />

          <button
            id="check-url-btn"
            type="submit"
            disabled={isLoading}
            className="shrink-0 inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-[#000000] hover:bg-neutral-800 active:scale-[0.98] text-white text-sm font-bold shadow-md transition-all disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>Checking...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-white" />
                <span>Check URL</span>
                <ArrowRight className="w-4 h-4 text-white" />
              </>
            )}
          </button>
        </div>

        {validationError && (
          <div
            id="url-input-error"
            className="flex items-center justify-center gap-1.5 mt-3 text-xs font-semibold text-red-600"
            role="alert"
          >
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{validationError}</span>
          </div>
        )}
      </form>

      {/* Security Microcopy with Lock Icon */}
      <div className="flex items-center justify-center gap-1.5 mt-2.5 sm:mt-3 text-[11px] sm:text-[11.5px] text-slate-500 font-medium text-center">
        <Lock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
        <span>URLs are analyzed via secure API. No browsing history or cookies are transmitted or stored client-side.</span>
      </div>
    </div>
  );
};
