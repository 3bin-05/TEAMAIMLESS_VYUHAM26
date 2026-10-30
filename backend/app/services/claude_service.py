from app.core.config import settings


async def explain_evidence(evidence: dict) -> dict:
    if not settings.ANTHROPIC_API_KEY:
        return {
            "status": "unavailable",
            "explanation": "Claude API key not configured"
        }

    # We will implement the actual Claude API call after
    # the evidence schema and deterministic policy are ready.
    return {
        "status": "not_configured",
        "explanation": "Claude evidence analysis is not implemented yet"
    }