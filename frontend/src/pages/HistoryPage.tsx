import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient, ApiError } from '../services/api-client';
import type { ScanHistoryItem, Verdict } from '../types/api';
import {
  History,
  Search,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  AlertCircle,
  RotateCcw,
  ChevronRight,
  Inbox,
  Settings,
} from 'lucide-react';

export const HistoryPage: React.FC = () => {
  const [historyItems, setHistoryItems] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchHistory = async () => {
    setLoading(true);
    setErrorMessage(null);

    try {
      const data = await apiClient.getHistory();
      setHistoryItems(data);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 404) {
          setErrorMessage('The /api/v1/history endpoint is not yet implemented or exposed by the active backend.');
        } else {
          setErrorMessage(err.message);
        }
      } else {
        setErrorMessage(
          `Unable to connect to AEGIS backend at ${apiClient.getBaseUrl()}. Please verify the service is running. (Failed to fetch)`
        );
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // Filter actual returned items (no mock data!)
  const filteredItems = historyItems.filter((item) => {
    const matchesVerdict = verdictFilter === 'ALL' || item.verdict === verdictFilter;
    const matchesSearch =
      !searchQuery.trim() ||
      item.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.domain && item.domain.toLowerCase().includes(searchQuery.toLowerCase())) ||
      item.scan_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesVerdict && matchesSearch;
  });

  const getVerdictBadge = (verdict: Verdict) => {
    switch (verdict) {
      case 'SAFE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-neutral-100 text-neutral-800 border border-neutral-300">
            <ShieldCheck className="w-3.5 h-3.5 text-neutral-800" />
            <span>SAFE</span>
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-neutral-200 text-neutral-900 border border-neutral-400">
            <AlertTriangle className="w-3.5 h-3.5 text-neutral-900" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-black text-white">
            <ShieldAlert className="w-3.5 h-3.5 text-white" />
            <span>CRITICAL</span>
          </span>
        );
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-neutral-100 text-neutral-600 border border-neutral-200">
            <AlertCircle className="w-3.5 h-3.5 text-neutral-500" />
            <span>UNVERIFIED</span>
          </span>
        );
    }
  };

  return (
    <div className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <History className="w-7 h-7 text-black stroke-[2.2]" />
            <h1 className="text-3xl sm:text-4xl font-extrabold text-neutral-900 tracking-tight">
              Scan History
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-neutral-500 mt-1">
            Real scan records synchronized from the backend persistence service
          </p>
        </div>

        <button
          type="button"
          onClick={fetchHistory}
          disabled={loading}
          className="inline-flex items-center gap-2 h-10 px-4 rounded-xl bg-white hover:bg-neutral-50 border border-neutral-200/90 text-neutral-800 text-xs font-semibold shadow-xs disabled:opacity-50 transition-colors self-start sm:self-auto"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Horizontal Divider */}
      <div className="border-b border-black/[0.06] mb-12" />

      {/* Loading state */}
      {loading && (
        <div className="py-24 flex flex-col items-center justify-center text-neutral-400">
          <RotateCcw className="w-8 h-8 animate-spin text-black mb-3" />
          <p className="text-sm font-medium text-neutral-700">Fetching history records from backend...</p>
        </div>
      )}

      {/* Endpoint Unavailable / Error state (Matches user reference exactly) */}
      {!loading && errorMessage && (
        <div className="max-w-2xl mx-auto bg-white rounded-3xl border border-neutral-200/80 shadow-[0_4px_30px_rgba(0,0,0,0.03)] p-10 sm:p-14 text-center">
          {/* Circular exclamation icon */}
          <div className="w-14 h-14 rounded-full border-2 border-black flex items-center justify-center mx-auto mb-6 text-black font-extrabold text-2xl select-none">
            !
          </div>

          <h2 className="text-2xl font-extrabold text-neutral-900 tracking-tight mb-2.5">
            Unable to Retrieve History
          </h2>

          <p className="text-xs sm:text-sm text-neutral-500 leading-relaxed max-w-lg mx-auto mb-5 font-normal">
            {errorMessage}
          </p>

          <div className="flex items-center justify-center gap-2 mb-8">
            <span className="text-xs text-neutral-500 font-medium">Endpoint :</span>
            <code className="bg-neutral-100/90 text-neutral-800 font-mono text-xs font-semibold px-2.5 py-1 rounded-lg border border-neutral-200/60">
              GET /api/v1/history
            </code>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <button
              type="button"
              onClick={fetchHistory}
              className="w-full sm:w-auto h-11 px-5 rounded-xl bg-neutral-950 hover:bg-black text-white text-xs font-bold flex items-center justify-center gap-2 shadow-xs transition-colors"
            >
              <RotateCcw className="w-4 h-4 text-white" />
              <span>Retry Connection</span>
            </button>

            <Link
              to="/settings"
              className="w-full sm:w-auto h-11 px-5 rounded-xl bg-white hover:bg-neutral-50 border border-neutral-200 text-neutral-800 text-xs font-bold flex items-center justify-center gap-2 shadow-xs transition-colors"
            >
              <Settings className="w-4 h-4 text-neutral-700" />
              <span>Check Backend Settings</span>
            </Link>
          </div>
        </div>
      )}

      {/* Empty State (when backend returns [] without error) */}
      {!loading && !errorMessage && historyItems.length === 0 && (
        <div className="max-w-2xl mx-auto bg-white rounded-3xl border border-neutral-200/80 shadow-[0_4px_30px_rgba(0,0,0,0.03)] p-10 sm:p-14 text-center">
          <div className="w-16 h-16 rounded-2xl bg-neutral-100 border border-neutral-200 flex items-center justify-center text-neutral-700 mx-auto mb-4">
            <Inbox className="w-8 h-8" />
          </div>
          <h2 className="text-2xl font-extrabold text-neutral-900 tracking-tight mb-2">No Scan History Recorded</h2>
          <p className="text-xs sm:text-sm text-neutral-500 mt-1 max-w-sm mx-auto leading-relaxed mb-6">
            No scans have been performed yet. Once URLs are analyzed, real verified scan records will appear here.
          </p>
          <Link
            to="/"
            className="inline-flex items-center gap-2 h-11 px-6 rounded-xl bg-neutral-950 hover:bg-black text-white text-xs font-bold shadow-xs transition-colors"
          >
            Run First URL Scan
          </Link>
        </div>
      )}

      {/* Table & Controls (Rendered ONLY when real records exist) */}
      {!loading && !errorMessage && historyItems.length > 0 && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            {/* Search */}
            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 text-neutral-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by URL or ID..."
                className="w-full pl-9 pr-4 py-2 text-xs font-mono bg-white border border-neutral-200/90 rounded-xl focus:outline-none focus:border-neutral-400 shadow-xs"
              />
            </div>

            {/* Verdict Filter Buttons */}
            <div className="flex items-center gap-1 self-start sm:self-auto bg-neutral-100 p-1 rounded-xl border border-neutral-200/80 text-xs">
              {(['ALL', 'SAFE', 'SUSPICIOUS', 'CRITICAL'] as const).map((filter) => (
                <button
                  key={filter}
                  type="button"
                  onClick={() => setVerdictFilter(filter)}
                  className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
                    verdictFilter === filter
                      ? 'bg-black text-white shadow-xs'
                      : 'text-neutral-600 hover:text-black'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>

          {/* Results List */}
          <div className="bg-white rounded-2xl border border-neutral-200/80 shadow-[0_4px_25px_rgba(0,0,0,0.03)] divide-y divide-neutral-100 overflow-hidden">
            {filteredItems.map((item) => (
              <Link
                key={item.scan_id}
                to={`/history/${encodeURIComponent(item.scan_id)}`}
                className="flex items-center justify-between p-4 hover:bg-neutral-50/80 transition-colors group"
              >
                <div className="min-w-0 flex-1 pr-4">
                  <div className="flex items-center gap-2 mb-1">
                    {getVerdictBadge(item.verdict)}
                    {item.risk_score !== null && item.risk_score !== undefined && (
                      <span className="text-[11px] font-mono font-medium text-neutral-500">
                        Score: {item.risk_score}/100
                      </span>
                    )}
                    <span className="text-[11px] font-mono text-neutral-400 ml-auto sm:ml-0">
                      {new Date(item.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <p className="font-mono text-xs text-neutral-800 font-medium truncate group-hover:text-black transition-colors">
                    {item.url}
                  </p>
                </div>

                <div className="shrink-0 flex items-center text-neutral-400 group-hover:text-black transition-colors">
                  <ChevronRight className="w-4 h-4" />
                </div>
              </Link>
            ))}

            {filteredItems.length === 0 && (
              <div className="p-8 text-center text-xs text-neutral-500">
                No matching scans found for current filter.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
