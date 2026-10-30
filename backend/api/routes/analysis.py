import logging
from fastapi import APIRouter, Depends, HTTPException, status
from api.schemas.analysis import AnalyzeRequest, AnalyzeResponse, BatchAnalyzeRequest, BatchAnalyzeResponse, ClassificationEnum
from api.dependencies import get_aegis_engine
from aegis_engine import AegisEngine, AnalysisResult
from aegis_engine.exceptions import EngineError

logger = logging.getLogger("aegis.api")

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


def _run_analysis(payload: AnalyzeRequest, engine: AegisEngine) -> AnalyzeResponse:
    """Shared analysis logic for both /analyze and /analyze-url endpoints."""
    logger.info(f"Received analysis request for URL length {len(payload.url)}")

    # Execute Aegis Engine pipeline
    result: AnalysisResult = engine.analyze(payload.url)

    # Validate risk score range strictly (0 <= risk_score <= 100)
    if not isinstance(result.risk_score, int) or not (0 <= result.risk_score <= 100):
        logger.critical(f"Engine returned invalid risk score out of bounds: {result.risk_score}")
        raise EngineError(f"Internal risk score out of bounds [0-100]: {result.risk_score}")

    # Validate classification enum strictly
    try:
        classification_enum = ClassificationEnum(result.classification)
    except ValueError:
        logger.critical(f"Engine returned invalid classification value: {result.classification}")
        raise EngineError(f"Internal classification invalid: {result.classification}")

    return AnalyzeResponse(
        url=result.url,
        classification=classification_enum,
        risk_score=result.risk_score,
        reasons=result.reasons,
        signals=result.signals,
        ai=result.ai,
        model_version=result.model_version,
        cached=result.cached,
        analysis_time_ms=result.analysis_time_ms,
    )


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Primary URL security analysis endpoint",
    description="Analyzes a target URL for phishing threats using ML classification, cybersecurity analysis, and advisory local AI.",
)
def analyze_url(
    payload: AnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> AnalyzeResponse:
    """Analyze input URL and return structured security classification and signals."""
    return _run_analysis(payload, engine)


@router.post(
    "/analyze-url",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias URL security analysis endpoint",
    description="Backward-compatible alias for POST /api/v1/analyze.",
    include_in_schema=True,
)
def analyze_url_alias(
    payload: AnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> AnalyzeResponse:
    """Alias endpoint — delegates to the same analysis pipeline as /analyze."""
    return _run_analysis(payload, engine)


@router.post(
    "/analyze-batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch URL security analysis endpoint",
    description="Analyzes multiple URLs in batch for search engine result annotations and real-time page scanning.",
)
def analyze_batch(
    payload: BatchAnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> BatchAnalyzeResponse:
    """Analyze a batch of URLs concurrently or sequentially and return verified results."""
    results: list[AnalyzeResponse] = []
    seen = set()
    for raw_url in payload.urls:
        url_str = (raw_url or "").strip()
        if not url_str or url_str in seen:
            continue
        seen.add(url_str)
        try:
            req = AnalyzeRequest(url=url_str)
            res = _run_analysis(req, engine)
            results.append(res)
        except Exception as err:
            logger.warning(f"Batch item analysis failed for {url_str}: {err}")
            continue

    return BatchAnalyzeResponse(results=results, total=len(results))

