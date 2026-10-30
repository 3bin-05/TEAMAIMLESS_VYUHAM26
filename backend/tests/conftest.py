import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import get_db
from app.db.database import Base
from app.main import app

# Shared isolated in-memory SQLite database across all test suites
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine
)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Configure global dependency override
app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def clean_database_tables():
    """Recreates fresh tables before each test to guarantee complete isolation."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def mock_analyzer_ai_router(request, monkeypatch):
    """Mocks ai_router.analyze in analyzer.py for non-AI test suites so they run instantaneously."""
    if "test_hybrid_ai" in request.node.nodeid:
        yield
        return

    from app.services.ai.ai_schemas import AIAnalysisResult, AIStructuredAnalysis

    async def _mock_analyze(*args, **kwargs):
        return AIAnalysisResult(
            provider="mock_ai",
            model="mock-fast-v1",
            status="completed",
            analysis=AIStructuredAnalysis(
                verdict_interpretation="LEGITIMATE",
                explanation="Mock AI explanation for fast test execution.",
                suspicious_indicators=[],
                benign_indicators=["Valid structure"],
                confidence_score=0.95,
                recommended_action="ALLOW",
                next_steps="None"
            ),
            latency_ms=1.0,
            cloud_used=False,
        )

    from app.services.ai.ai_router import router as ai_router

    monkeypatch.setattr(ai_router, "analyze", _mock_analyze)
    yield
