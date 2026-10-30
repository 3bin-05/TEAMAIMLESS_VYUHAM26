import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import logger, sanitize_url_for_logging
from app.db.database import get_db
from app.db.entities import URLScan, UserDecision
from app.schemas.analysis import (
    AnalysisChecks,
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    CheckResult,
    DecisionRequest,
    DecisionResponse,
    HealthResponse,
    ScanDetailResponse,
    ScanHistoryItem,
    ScanStatusResponse,
)
from app.utils.url import extract_domain, normalize_url

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Backend Health Check",
    description="Returns service status and active environment without exposing sensitive configuration."
)
def health_check() -> HealthResponse:
    return HealthResponse(
        app_name=settings.APP_NAME,
        status="healthy",
        environment=settings.APP_ENV
    )


import asyncio
from app.services.analyzer import analyze_url
from app.services.ai.ai_router import router as ai_router
from app.services.ai.ai_schemas import AIStatusResponse


@router.get(
    "/ai/status",
    response_model=AIStatusResponse,
    summary="Get Hybrid AI Intelligence Status",
    description="Reports local Ollama availability, discovered models, verified inference status, and Claude cloud readiness without exposing secrets."
)
async def get_ai_status() -> AIStatusResponse:
    return await ai_router.get_status()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze URL for Phishing and Threat Indicators",
    description="Coordinates multi-source threat intelligence (ML, Google Safe Browsing, VirusTotal, RDAP, AI) and stores structured provider evidence in the database."
)
async def analyze_url_endpoint(
    request: AnalyzeRequest,
    db: Session = Depends(get_db)
) -> AnalyzeResponse:
    raw_url = str(request.url)
    logger.info(f"Received analysis request for URL: {sanitize_url_for_logging(raw_url)} [Source: {request.source}]")
    return await analyze_url(
        raw_url,
        source=request.source,
        allow_cloud_ai=request.allow_cloud_ai,
        db=db
    )


@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    summary="Batch URL Analysis",
    description="Analyzes up to 20 URLs concurrently using independent detection services."
)
async def analyze_batch_endpoint(
    request: BatchAnalyzeRequest,
    db: Session = Depends(get_db)
) -> BatchAnalyzeResponse:
    logger.info(f"Received batch analysis request with {len(request.urls)} URLs [Source: {request.source}]")
    tasks = [
        analyze_url(str(u), source=request.source, allow_cloud_ai=request.allow_cloud_ai, db=db)
        for u in request.urls
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    batch_results = []
    for u, res in zip(request.urls, results):
        url_str = str(u)
        if isinstance(res, Exception):
            batch_results.append({
                "url": url_str,
                "status": "failed",
                "verdict": "INSUFFICIENT_EVIDENCE",
                "action": "WARN",
                "reason": str(res)
            })
        else:
            dumped = res.model_dump()
            dumped["url"] = url_str
            batch_results.append(dumped)

    return BatchAnalyzeResponse(
        status="completed",
        count=len(batch_results),
        results=batch_results,
        urls=[str(u) for u in request.urls]
    )


@router.get(
    "/status/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Retrieve Scan Status",
    description="Returns processing status of an ongoing or completed scan."
)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db)
) -> ScanStatusResponse:
    record = db.query(URLScan).filter(URLScan.scan_id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )
    return ScanStatusResponse(
        scan_id=record.scan_id,
        status=record.status,
        progress=100 if record.status == "completed" else 50
    )


@router.get(
    "/verdict/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve Scan Verdict",
    description="Returns the security verdict and risk evaluation for a specific scan ID."
)
def get_verdict(
    scan_id: str,
    db: Session = Depends(get_db)
) -> ScanDetailResponse:
    return get_scan_details(scan_id, db)


@router.get(
    "/history",
    response_model=list[ScanHistoryItem],
    summary="Retrieve Scan History",
    description="Returns a paginated list of previous scans from SQLite, ordered by newest first."
)
def get_history(
    limit: int = Query(default=50, ge=1, le=100, description="Max records to return (1-100)"),
    db: Session = Depends(get_db)
) -> list[ScanHistoryItem]:
    records = (
        db.query(URLScan)
        .order_by(URLScan.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        ScanHistoryItem(
            scan_id=item.scan_id,
            url=item.original_url,
            domain=item.domain,
            verdict=item.verdict,  # type: ignore
            risk_score=item.risk_score,
            action=item.action,
            status=item.status,
            timestamp=item.created_at,
            created_at=item.created_at
        )
        for item in records
    ]


@router.get(
    "/history/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve Scan Details",
    description="Returns detailed scan telemetry and provider findings for a specific scan ID."
)
def get_scan_details(
    scan_id: str,
    db: Session = Depends(get_db)
) -> ScanDetailResponse:
    record = db.query(URLScan).filter(URLScan.scan_id == scan_id).first()

    if not record:
        logger.warning(f"Scan details requested for non-existent scan ID: {scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    decision = record.checks.get("decision") if isinstance(record.checks, dict) else {}

    return ScanDetailResponse(
        scan_id=record.scan_id,
        original_url=record.original_url,
        normalized_url=record.normalized_url,
        domain=record.domain,
        status=record.status,
        verdict=record.verdict,  # type: ignore
        risk_score=record.risk_score,
        action=record.action,
        reason=record.reason,
        source=record.source,
        checks=record.checks,
        confidence_level=decision.get("confidence_level") if isinstance(decision, dict) else None,
        evidence_completeness=decision.get("evidence_completeness") if isinstance(decision, dict) else None,
        decision_details=decision if isinstance(decision, dict) and decision else None,
        created_at=record.created_at
    )


@router.post(
    "/decisions",
    response_model=DecisionResponse,
    summary="Record User Decision",
    description="Saves a user override decision (PROCEED or CANCEL) for an existing scan record."
)
def save_user_decision(
    request: DecisionRequest,
    db: Session = Depends(get_db)
) -> DecisionResponse:
    record = db.query(URLScan).filter(URLScan.scan_id == request.scan_id).first()

    if not record:
        logger.warning(f"Decision submitted for non-existent scan ID: {request.scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot record decision: scan with ID '{request.scan_id}' not found."
        )

    # Normalize decision to uppercase
    norm_decision = request.decision.strip().upper()
    if "PROCEED" in norm_decision:
        norm_decision = "PROCEED"
    elif "CANCEL" in norm_decision:
        norm_decision = "CANCEL"
    else:
        norm_decision = "PROCEED" if norm_decision.startswith("P") else "CANCEL"

    decision_record = UserDecision(
        decision_id=str(uuid.uuid4()),
        scan_id=request.scan_id,
        decision=norm_decision
    )

    db.add(decision_record)
    db.commit()
    db.refresh(decision_record)

    logger.info(f"Recorded user decision '{norm_decision}' for scan {request.scan_id}")

    return DecisionResponse(
        status="saved",
        decision_id=decision_record.decision_id,
        scan_id=decision_record.scan_id,
        decision=decision_record.decision,  # type: ignore
        created_at=decision_record.created_at
    )