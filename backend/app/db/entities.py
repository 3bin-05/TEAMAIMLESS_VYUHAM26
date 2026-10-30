import uuid
from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.db.database import Base


class URLScan(Base):
    """Stores URL analysis requests and security verdicts."""
    __tablename__ = "url_scans"

    scan_id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    original_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)

    # Initial nullable attributes for Phase 1
    verdict = Column(String(32), nullable=True)     # SAFE, SUSPICIOUS, CRITICAL, INSUFFICIENT_EVIDENCE
    risk_score = Column(Integer, nullable=True)     # 0 - 100
    action = Column(String(32), nullable=True)      # BLOCK, WARN, ALLOW, NONE

    source = Column(String(64), default="extension", nullable=False)  # extension, dashboard, search_guard
    status = Column(String(32), default="pending", nullable=False)    # pending, processing, completed, failed

    # Additional contextual fields
    reason = Column(Text, nullable=True)
    checks = Column(JSON, nullable=True)
    user_id = Column(String(64), nullable=True, index=True)  # Reserved for future user/session ownership

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relationships
    detection_results = relationship(
        "DetectionResult",
        back_populates="scan",
        cascade="all, delete-orphan"
    )
    user_decisions = relationship(
        "UserDecision",
        back_populates="scan",
        cascade="all, delete-orphan"
    )


class DetectionResult(Base):
    """Stores individual intelligence provider results for a scan."""
    __tablename__ = "detection_results"

    result_id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(
        String(64),
        ForeignKey("url_scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    provider = Column(String(64), nullable=False)  # ML, Google Safe Browsing, VirusTotal, RDAP, DomainShield, AI
    status = Column(String(32), nullable=False)    # provider execution status (e.g., success, failed, skipped)
    result_data = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relationship back to scan
    scan = relationship("URLScan", back_populates="detection_results")


class UserDecision(Base):
    """Stores user override or confirmation decisions for suspicious/blocked scans."""
    __tablename__ = "user_decisions"

    decision_id = Column(String(64), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(
        String(64),
        ForeignKey("url_scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    decision = Column(String(32), nullable=False)  # PROCEED or CANCEL
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relationship back to scan
    scan = relationship("URLScan", back_populates="user_decisions")