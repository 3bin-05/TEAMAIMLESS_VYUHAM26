import os
import time
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict

from ml_model import predict_url, normalize_url, MODEL_VERSION
from ml_model.exceptions import InvalidURLError
from cache import MemoryCache
from cyber_analysis import CyberOrchestrator, CyberAnalysisResult
from cyber_analysis.threat_intel.official_domains import check_official_domain, check_search_engine_query
from local_ai import LocalAIAnalyzer, AIAnalysisResult
from .risk_scorer import calculate_risk_score
from .decision_engine import DecisionConfig, classify_risk, generate_reasons
from .exceptions import EngineError

logger = logging.getLogger("aegis.engine")


@dataclass
class AnalysisResult:
    """Standard contract for Aegis Engine analysis output."""
    url: str
    classification: str
    risk_score: int
    cached: bool
    reasons: List[str]
    signals: Dict[str, Any]
    model_version: str
    analysis_time_ms: float
    ai: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result object to dictionary."""
        return asdict(self)


class AegisEngine:
    """Central orchestration engine for AEGIS phishing prevention analysis."""

    def __init__(
        self,
        cache: Optional[MemoryCache] = None,
        decision_config: Optional[DecisionConfig] = None,
        predictor_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
        cyber_orchestrator: Optional[CyberOrchestrator] = None,
        enable_cyber_analysis: Optional[bool] = None,
        ai_analyzer: Optional[LocalAIAnalyzer] = None,
        enable_ai: Optional[bool] = None,
    ):
        self.cache = cache if cache is not None else MemoryCache()
        self.decision_config = decision_config or DecisionConfig()
        self.predictor_fn = predictor_fn or predict_url
        self.cyber_orchestrator = cyber_orchestrator or CyberOrchestrator()

        if enable_cyber_analysis is not None:
            self.enable_cyber_analysis = enable_cyber_analysis
        elif cyber_orchestrator is not None:
            self.enable_cyber_analysis = True
        else:
            self.enable_cyber_analysis = (
                os.getenv("AEGIS_CYBER_ANALYSIS_ENABLED", "false").lower() == "true"
            )

        self.ai_analyzer = ai_analyzer or LocalAIAnalyzer()
        if enable_ai is not None:
            self.enable_ai = enable_ai
        elif ai_analyzer is not None:
            self.enable_ai = True
        else:
            self.enable_ai = (
                os.getenv("AEGIS_AI_ENABLED", "false").lower() == "true"
            )

    def analyze(
        self,
        url: str,
        force_cyber_analysis: Optional[bool] = None,
        force_ai_analysis: Optional[bool] = None,
    ) -> AnalysisResult:
        """Run complete Aegis security analysis on the provided URL with multi-tiered fallback.

        Args:
            url: The input URL string.
            force_cyber_analysis: Override whether deep cybersecurity analysis is executed.
            force_ai_analysis: Override whether Local AI context analysis is executed.

        Returns:
            AnalysisResult with classification, risk_score, reasons, signals, ai, etc.

        Raises:
            InvalidURLError: If the input URL is empty, None, or non-string.
        """
        if url is None or not isinstance(url, str):
            raise InvalidURLError(
                f"URL must be a non-empty string, got {type(url).__name__}"
            )

        if not url.strip():
            raise InvalidURLError("URL string cannot be empty or whitespace-only")

        canonical_url = normalize_url(url)
        start_time = time.perf_counter()

        try:
            return self._execute_pipeline(
                url, canonical_url, start_time, force_cyber_analysis, force_ai_analysis
            )
        except InvalidURLError:
            raise
        except Exception as err:
            logger.error(
                f"Aegis primary pipeline encountered error: {err}. Activating Emergency ML Fallback.",
                exc_info=True,
            )
            return self._emergency_fallback(url, canonical_url, str(err), start_time)

    def _execute_pipeline(
        self,
        url: str,
        canonical_url: str,
        start_time: float,
        force_cyber_analysis: Optional[bool] = None,
        force_ai_analysis: Optional[bool] = None,
    ) -> AnalysisResult:
        active_version = MODEL_VERSION

        # 1. Trust Cache lookup (Tier 1 Fallback / Fast-path)
        cached_data = self.cache.get(
            canonical_url, active_model_version=active_version
        )
        if cached_data is not None:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return AnalysisResult(
                url=canonical_url,
                classification=cached_data["classification"],
                risk_score=cached_data["risk_score"],
                cached=True,
                reasons=list(cached_data.get("reasons", [])),
                signals=dict(cached_data.get("signals", {})),
                model_version=cached_data.get("model_version", active_version),
                analysis_time_ms=elapsed_ms,
                ai=cached_data.get("ai"),
            )

        # 2. Official Restricted Domain Fast-Path (Government, Military, Academic, Bank, etc.)
        # Registration is legally restricted to verified organizations.
        # Zero resource waste: Never blacklisted, fixed reason, skips local LLM.
        official_info = check_official_domain(canonical_url)
        if official_info:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reasons = [
                f"Verified Official Restricted Domain ({official_info.category} - {official_info.name}).",
                f"Registration is strictly restricted to {official_info.intended_org}. Cannot be registered by the public.",
                official_info.description,
            ]
            signals = {
                "official_domain": official_info.to_dict(),
                "fast_path": True,
                "resource_saving": True,
                "ml_probability": 0.0,
                "ml_prediction": 0,
                "ml_label": "BENIGN",
            }
            ai_data = {
                "available": False,
                "status": "bypassed_official_verified",
                "summary": f"Fast-path verified {official_info.name}. Local LLM bypassed to conserve system resources.",
                "final_verdict": "SAFE",
                "final_score": 0,
            }
            res = AnalysisResult(
                url=canonical_url,
                classification="SAFE",
                risk_score=0,
                cached=False,
                reasons=reasons,
                signals=signals,
                model_version=active_version,
                analysis_time_ms=elapsed_ms,
                ai=ai_data,
            )
            self.cache.set(canonical_url, res.to_dict(), model_version=active_version)
            return res

        # 3. Search Engine & Browser Keyword Search Fast-Path
        # Browser searches on Google, Bing, DuckDuckGo, etc., or keyword search phrases
        # are legitimate user search traffic and never phishing/malicious threats.
        search_info = check_search_engine_query(url, canonical_url)
        if search_info:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reasons = [
                f"Verified Search Engine Query ({search_info['name']}).",
                search_info.get("description", "Browser keyword searches and official search traffic are safe."),
            ]
            signals = {
                "search_engine_query": search_info,
                "fast_path": True,
                "resource_saving": True,
                "ml_probability": 0.0,
                "ml_prediction": 0,
                "ml_label": "BENIGN",
            }
            ai_data = {
                "available": False,
                "status": "bypassed_search_query",
                "summary": f"Browser search query ({search_info['name']}) verified safe. Deep probers and LLM bypassed.",
                "final_verdict": "SAFE",
                "final_score": 0,
            }
            res = AnalysisResult(
                url=canonical_url,
                classification="SAFE",
                risk_score=0,
                cached=False,
                reasons=reasons,
                signals=signals,
                model_version=active_version,
                analysis_time_ms=elapsed_ms,
                ai=ai_data,
            )
            self.cache.set(canonical_url, res.to_dict(), model_version=active_version)
            return res

        # 3. Local XGBoost ML Model Analysis (Tier 2 Primary Classifier)
        ml_result = self.predictor_fn(url)
        if not isinstance(ml_result, dict):
            raise EngineError(
                f"Predictor returned invalid result type: {type(ml_result).__name__}"
            )

        # 3. Cybersecurity & Threat Intel Analysis (Tier 3 Enrichment)
        should_run_cyber = (
            force_cyber_analysis
            if force_cyber_analysis is not None
            else self.enable_cyber_analysis
        )

        cyber_result: Optional[CyberAnalysisResult] = None
        cyber_signals: List[Any] = []

        if should_run_cyber:
            try:
                cyber_result = self.cyber_orchestrator.analyze(canonical_url)
                if cyber_result and cyber_result.signals:
                    cyber_signals = cyber_result.signals
            except Exception as cyber_err:
                logger.warning(
                    f"Cyber analysis encountered an error for {canonical_url}: {cyber_err}. "
                    f"Falling back to local ML heuristics."
                )
                cyber_signals = []

        # 4. Integrated Risk Scoring (DETERMINISTIC)
        risk_res = calculate_risk_score(ml_result, security_signals=cyber_signals)

        # 5. Decision Classification (DETERMINISTIC)
        classification = classify_risk(risk_res.score, self.decision_config)

        # 6. Reason Generation
        reasons = generate_reasons(
            classification, risk_res.score, ml_result, security_signals=cyber_signals
        )

        # 7. Aggregated Signals
        signals: Dict[str, Any] = {
            "ml_probability": ml_result.get("probability"),
            "ml_prediction": ml_result.get("prediction"),
            "ml_label": ml_result.get("label"),
        }

        if cyber_result is not None:
            signals["cyber_analysis"] = cyber_result.to_dict()

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        model_version = ml_result.get("model_version", active_version)

        result = AnalysisResult(
            url=canonical_url,
            classification=classification,
            risk_score=risk_res.score,
            cached=False,
            reasons=reasons,
            signals=signals,
            model_version=model_version,
            analysis_time_ms=elapsed_ms,
            ai=None,
        )

        # 8. Local AI Analysis (Tier 4 Advisory & Authoritative Override)
        # If AI is slow, offline, or times out, the deterministic result stands as fallback
        should_run_ai = (
            force_ai_analysis
            if force_ai_analysis is not None
            else self.enable_ai
        )

        if should_run_ai:
            try:
                ai_res = self.ai_analyzer.analyze(result)
                if ai_res:
                    result.ai = ai_res.to_dict()

                    # Apply LLM's authoritative verdict when available and valid
                    if ai_res.available and ai_res.final_verdict and ai_res.final_score is not None:
                        prev_classification = result.classification
                        prev_score = result.risk_score

                        verdict = ai_res.final_verdict.upper()
                        if verdict == "CRITICAL":
                            verdict = "MALICIOUS"
                        result.classification = verdict
                        result.risk_score = ai_res.final_score

                        if ai_res.final_verdict != prev_classification:
                            result.reasons.insert(
                                0,
                                f"AI Security Engine upgraded verdict from {prev_classification} "
                                f"to {ai_res.final_verdict} (score: {prev_score}→{ai_res.final_score}) "
                                f"based on holistic signal correlation and brand lookalike analysis."
                            )
                        else:
                            result.reasons.insert(
                                0,
                                f"AI Security Engine confirmed {ai_res.final_verdict} verdict "
                                f"(final score: {ai_res.final_score}/100)."
                            )

                        result.signals["deterministic_pre_ai"] = {
                            "classification": prev_classification,
                            "risk_score": prev_score,
                        }
                    else:
                        # AI unavailable or timed out: record graceful fallback
                        result.signals["ai_fallback"] = {
                            "active": True,
                            "reason": ai_res.error or f"AI status: {ai_res.status}",
                            "reverted_to": "deterministic",
                        }
            except Exception as e:
                logger.warning(f"Local AI failed for {canonical_url}: {e}. Falling back to deterministic.")
                result.ai = {
                    "available": False,
                    "status": "provider_error",
                    "error": str(e),
                }
                result.signals["ai_fallback"] = {
                    "active": True,
                    "reason": str(e),
                    "reverted_to": "deterministic",
                }

        # 9. Trust Cache Storage
        self.cache.set(
            canonical_url, result.to_dict(), model_version=model_version
        )

        return result

    def _emergency_fallback(
        self,
        url: str,
        canonical_url: str,
        error_msg: str,
        start_time: float,
    ) -> AnalysisResult:
        """Emergency Tier 1/2 Fallback: If deep analysis or pipeline crashes,
        safely fall back to the standalone local ML model and safe heuristics without failing open."""
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        try:
            ml_res = self.predictor_fn(url)
            prob = float(ml_res.get("probability", 0.5))
            score = int(prob * 100)

            if score >= self.decision_config.critical_threshold:
                classification = "MALICIOUS"
            elif score >= self.decision_config.safe_threshold:
                classification = "SUSPICIOUS"
            else:
                classification = "SAFE"

            reasons = [
                f"Emergency Fallback Mode active: primary pipeline encountered an issue ({error_msg}).",
                f"Classified via local XGBoost ML model with {round(prob * 100, 1)}% phishing probability."
            ]
            signals = {
                "fallback_mode": True,
                "fallback_reason": error_msg,
                "ml_probability": prob,
                "ml_label": ml_res.get("label", classification),
            }
        except Exception as ml_err:
            classification = "SUSPICIOUS"
            score = 50
            reasons = [
                f"Emergency Fallback Mode: Engine and ML failure ({error_msg}; {ml_err}).",
                "Flagged as SUSPICIOUS to protect the user."
            ]
            signals = {
                "fallback_mode": True,
                "fallback_reason": f"{error_msg} | {ml_err}",
                "ml_probability": 0.5,
                "ml_label": "UNKNOWN",
            }

        return AnalysisResult(
            url=canonical_url,
            classification=classification,
            risk_score=score,
            cached=False,
            reasons=reasons,
            signals=signals,
            model_version=MODEL_VERSION,
            analysis_time_ms=elapsed_ms,
            ai={
                "available": False,
                "status": "fallback_bypassed",
                "error": error_msg,
            },
        )
