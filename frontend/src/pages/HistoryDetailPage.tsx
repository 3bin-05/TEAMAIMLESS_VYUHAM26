import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { apiClient, ApiError } from '../services/api-client';
import type { AnalyzeResponse } from '../types/api';
import { VerdictCard } from '../components/verdict/VerdictCard';
import { ThreatReport } from '../components/evidence/ThreatReport';
import { ArrowLeft, Loader2, AlertCircle } from 'lucide-react';

export const HistoryDetailPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    const fetchDetail = async () => {
      setLoading(true);
      setErrorMessage(null);
      try {
        const result = await apiClient.getHistoryScan(scanId);
        setScan(result);
      } catch (err) {
        // Fallback to getVerdict if history/{scan_id} is not specifically separated
        try {
          const fallback = await apiClient.getVerdict(scanId);
          setScan(fallback);
        } catch {
          if (err instanceof ApiError) {
            setErrorMessage(err.message);
          } else {
            setErrorMessage('Unable to load scan record from backend.');
          }
        }
      } finally {
        setLoading(false);
      }
    };

    fetchDetail();
  }, [scanId]);

  return (
    <div className="flex-1 max-w-4xl w-full mx-auto px-4 sm:px-6 py-10">
      <div className="mb-6">
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scan History</span>
        </Link>
      </div>

      {loading && (
        <div className="py-20 flex flex-col items-center justify-center text-slate-400">
          <Loader2 className="w-8 h-8 animate-spin text-blue-600 mb-3" />
          <p className="text-sm font-medium">Loading scan verification report...</p>
        </div>
      )}

      {!loading && errorMessage && (
        <div className="p-8 rounded-2xl border border-red-200 bg-red-50 text-center">
          <AlertCircle className="w-8 h-8 text-red-600 mx-auto mb-2" />
          <h2 className="text-base font-bold text-red-900">Scan Record Not Found</h2>
          <p className="text-xs text-red-700 mt-1 max-w-md mx-auto">{errorMessage}</p>
        </div>
      )}

      {!loading && scan && (
        <div className="space-y-8">
          <VerdictCard
            verdict={scan.verdict}
            action={scan.action}
            riskScore={scan.risk_score}
            reason={scan.reason}
            reasons={scan.reasons}
            decisionDetails={scan.decision_details}
            confidenceLevel={scan.confidence_level}
            evidenceCompleteness={scan.evidence_completeness}
            url={scan.url || scan.original_url || ''}
            scanId={scan.scan_id}
            timestamp={scan.timestamp || scan.created_at}
            aiExplanation={scan.ai_explanation}
          />

          <ThreatReport
            checks={scan.checks}
            domainImpersonation={scan.domain_impersonation}
            aiExplanation={scan.ai_explanation}
            normalizedUrl={scan.normalized_url || scan.url || scan.original_url}
          />
        </div>
      )}
    </div>
  );
};
