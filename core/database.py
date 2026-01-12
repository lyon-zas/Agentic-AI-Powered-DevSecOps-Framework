"""
Database Module - SQLite/PostgreSQL persistence for agent state.

Provides a unified interface for storing:
- Vulnerability scan results
- Flaky test history
- Pipeline run records
- Agent session state

Supports SQLite for local development and PostgreSQL for production.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from contextlib import contextmanager
from enum import Enum

# SQLAlchemy imports
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
Base = declarative_base()


# ===== Enums =====

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(str, Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    IAST = "iast"


class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ===== Database Models =====

class Vulnerability(Base):
    """Stores vulnerability findings from security scans."""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    external_id = Column(String(255), index=True)  # CVE, CWE, or tool-specific ID
    scan_type = Column(String(50))  # sast, dast, sca, iast
    severity = Column(String(20))
    title = Column(String(500))
    description = Column(Text)
    file_path = Column(String(1000))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    recommendation = Column(Text)
    cwe_ids = Column(JSON)  # List of CWE IDs
    cvss_score = Column(Float)
    is_fixed = Column(Boolean, default=False)
    fixed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign key to scan
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    
    __table_args__ = (
        Index("idx_vuln_severity", "severity"),
        Index("idx_vuln_scan_type", "scan_type"),
    )


class Scan(Base):
    """Stores security scan records."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50))  # sast, dast, sca, iast
    target_path = Column(String(1000))
    status = Column(String(50))
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    risk_score = Column(Float)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    extra_data = Column(JSON)  # Additional scan-specific data
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", backref="scan")
    
    __table_args__ = (
        Index("idx_scan_type_status", "scan_type", "status"),
    )


class FlakyTest(Base):
    """Stores flaky test tracking data."""
    __tablename__ = "flaky_tests"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    test_id = Column(String(500), unique=True, index=True)
    test_name = Column(String(1000))
    file_path = Column(String(1000))
    
    # Bayesian tracking
    alpha = Column(Float, default=1.0)  # Prior successes
    beta = Column(Float, default=1.0)   # Prior failures
    total_runs = Column(Integer, default=0)
    failures = Column(Integer, default=0)
    p_failure = Column(Float, default=0.5)
    
    # Classification
    flakiness_type = Column(String(50))  # NOD, OD, NIO, etc.
    is_quarantined = Column(Boolean, default=False)
    quarantined_at = Column(DateTime, nullable=True)
    
    # Metadata
    last_failure_log = Column(Text)
    detected_patterns = Column(JSON)  # List of detected patterns
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PipelineRun(Base):
    """Stores CI/CD pipeline run records."""
    __tablename__ = "pipeline_runs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(255), unique=True, index=True)
    trigger = Column(String(255))  # push, pull_request, manual
    branch = Column(String(255))
    commit_sha = Column(String(64))
    status = Column(String(50))
    
    # Results
    vulnerabilities_found = Column(Integer, default=0)
    flaky_tests_detected = Column(Integer, default=0)
    tests_impacted = Column(Integer, default=0)
    decision = Column(String(50))  # approve, review, block
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float)
    
    # Extra data
    extra_data = Column(JSON)


class AgentState(Base):
    """Stores persistent agent session state."""
    __tablename__ = "agent_states"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_name = Column(String(255), index=True)
    session_id = Column(String(255), index=True)
    state_key = Column(String(255))
    state_value = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_agent_session_key", "agent_name", "session_id", "state_key", unique=True),
    )


# ===== Database Manager =====

class DatabaseManager:
    """
    Manages database connections and operations.
    
    Supports SQLite (default for development) and PostgreSQL (production).
    """
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure single database connection."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, db_url: Optional[str] = None):
        """
        Initialize database connection.
        
        Args:
            db_url: Database URL. If not provided, uses DATABASE_URL env var
                   or defaults to SQLite.
        """
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self.db_url = db_url or os.getenv(
            "DATABASE_URL",
            "sqlite:///./devsecops.db"
        )
        
        # Handle PostgreSQL URL format from some cloud providers
        if self.db_url.startswith("postgres://"):
            self.db_url = self.db_url.replace("postgres://", "postgresql://", 1)
        
        # Create engine with appropriate settings
        if "sqlite" in self.db_url:
            # SQLite-specific settings
            self.engine = create_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=os.getenv("DB_ECHO", "false").lower() == "true"
            )
        else:
            # PostgreSQL settings
            self.engine = create_engine(
                self.db_url,
                pool_size=5,
                max_overflow=10,
                echo=os.getenv("DB_ECHO", "false").lower() == "true"
            )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        self._initialized = True
        logger.info(f"Database initialized: {self._mask_url(self.db_url)}")
    
    def _mask_url(self, url: str) -> str:
        """Mask sensitive parts of database URL for logging."""
        if "@" in url:
            parts = url.split("@")
            return f"***@{parts[-1]}"
        return url
    
    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created successfully")
    
    def drop_tables(self):
        """Drop all database tables. USE WITH CAUTION."""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")
    
    @contextmanager
    def get_session(self) -> Session:
        """Get a database session with automatic cleanup."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    # ===== Vulnerability Operations =====
    
    def add_vulnerability(self, vuln_data: Dict[str, Any], scan_id: Optional[int] = None) -> int:
        """Add a vulnerability to the database."""
        with self.get_session() as session:
            vuln = Vulnerability(
                external_id=vuln_data.get("id") or vuln_data.get("external_id"),
                scan_type=vuln_data.get("scan_type", "unknown"),
                severity=vuln_data.get("severity", "medium"),
                title=vuln_data.get("title") or vuln_data.get("type", ""),
                description=vuln_data.get("description") or vuln_data.get("message", ""),
                file_path=vuln_data.get("file_path", ""),
                line_number=vuln_data.get("line_number") or vuln_data.get("start_line", 0),
                code_snippet=vuln_data.get("code_snippet", ""),
                recommendation=vuln_data.get("recommendation") or vuln_data.get("fix", ""),
                cwe_ids=vuln_data.get("cwe_ids", []),
                cvss_score=vuln_data.get("cvss_score"),
                scan_id=scan_id,
            )
            session.add(vuln)
            session.flush()
            return vuln.id
    
    def get_vulnerabilities(
        self,
        scan_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_fixed: Optional[bool] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities with optional filters."""
        with self.get_session() as session:
            query = session.query(Vulnerability)
            
            if scan_type:
                query = query.filter(Vulnerability.scan_type == scan_type)
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            if is_fixed is not None:
                query = query.filter(Vulnerability.is_fixed == is_fixed)
            
            query = query.order_by(Vulnerability.created_at.desc()).limit(limit)
            
            return [self._vuln_to_dict(v) for v in query.all()]
    
    def mark_vulnerability_fixed(self, vuln_id: int) -> bool:
        """Mark a vulnerability as fixed."""
        with self.get_session() as session:
            vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if vuln:
                vuln.is_fixed = True
                vuln.fixed_at = datetime.utcnow()
                return True
            return False
    
    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability model to dictionary."""
        return {
            "id": vuln.id,
            "external_id": vuln.external_id,
            "scan_type": vuln.scan_type,
            "severity": vuln.severity,
            "title": vuln.title,
            "description": vuln.description,
            "file_path": vuln.file_path,
            "line_number": vuln.line_number,
            "cwe_ids": vuln.cwe_ids,
            "cvss_score": vuln.cvss_score,
            "is_fixed": vuln.is_fixed,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
        }
    
    # ===== Scan Operations =====
    
    def create_scan(self, scan_data: Dict[str, Any]) -> int:
        """Create a new scan record."""
        with self.get_session() as session:
            scan = Scan(
                scan_type=scan_data.get("scan_type", "unknown"),
                target_path=scan_data.get("target_path", ""),
                status=scan_data.get("status", "running"),
                extra_data=scan_data.get("metadata", {}),
            )
            session.add(scan)
            session.flush()
            return scan.id
    
    def complete_scan(self, scan_id: int, results: Dict[str, Any]) -> bool:
        """Update scan with completion results."""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = results.get("status", "completed")
                scan.completed_at = datetime.utcnow()
                scan.total_findings = results.get("total_findings", 0)
                scan.critical_count = results.get("by_severity", {}).get("critical", 0)
                scan.high_count = results.get("by_severity", {}).get("high", 0)
                scan.medium_count = results.get("by_severity", {}).get("medium", 0)
                scan.low_count = results.get("by_severity", {}).get("low", 0)
                scan.risk_score = results.get("risk_score", 0)
                return True
            return False
    
    def get_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scan records."""
        with self.get_session() as session:
            scans = session.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
            return [
                {
                    "id": s.id,
                    "scan_type": s.scan_type,
                    "target_path": s.target_path,
                    "status": s.status,
                    "total_findings": s.total_findings,
                    "risk_score": s.risk_score,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                }
                for s in scans
            ]
    
    # ===== Flaky Test Operations =====
    
    def upsert_flaky_test(self, test_data: Dict[str, Any]) -> int:
        """Insert or update a flaky test record."""
        with self.get_session() as session:
            test_id = test_data.get("test_id")
            flaky = session.query(FlakyTest).filter(FlakyTest.test_id == test_id).first()
            
            if flaky:
                # Update existing
                flaky.alpha = test_data.get("alpha", flaky.alpha)
                flaky.beta = test_data.get("beta", flaky.beta)
                flaky.total_runs = test_data.get("total_runs", flaky.total_runs)
                flaky.failures = test_data.get("failures", flaky.failures)
                flaky.p_failure = test_data.get("p_failure", flaky.p_failure)
                flaky.is_quarantined = test_data.get("is_quarantined", flaky.is_quarantined)
                if test_data.get("detected_patterns"):
                    flaky.detected_patterns = test_data["detected_patterns"]
            else:
                # Create new
                flaky = FlakyTest(
                    test_id=test_id,
                    test_name=test_data.get("test_name", test_id),
                    file_path=test_data.get("file_path", ""),
                    alpha=test_data.get("alpha", 1.0),
                    beta=test_data.get("beta", 1.0),
                    total_runs=test_data.get("total_runs", 0),
                    failures=test_data.get("failures", 0),
                    p_failure=test_data.get("p_failure", 0.5),
                    flakiness_type=test_data.get("flakiness_type"),
                    is_quarantined=test_data.get("is_quarantined", False),
                    detected_patterns=test_data.get("detected_patterns", []),
                )
                session.add(flaky)
            
            session.flush()
            return flaky.id
    
    def get_flaky_tests(
        self,
        quarantined_only: bool = False,
        min_p_failure: float = 0.0,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get flaky test records."""
        with self.get_session() as session:
            query = session.query(FlakyTest)
            
            if quarantined_only:
                query = query.filter(FlakyTest.is_quarantined == True)
            if min_p_failure > 0:
                query = query.filter(FlakyTest.p_failure >= min_p_failure)
            
            query = query.order_by(FlakyTest.p_failure.desc()).limit(limit)
            
            return [
                {
                    "id": t.id,
                    "test_id": t.test_id,
                    "test_name": t.test_name,
                    "p_failure": t.p_failure,
                    "total_runs": t.total_runs,
                    "failures": t.failures,
                    "is_quarantined": t.is_quarantined,
                    "flakiness_type": t.flakiness_type,
                    "detected_patterns": t.detected_patterns,
                }
                for t in query.all()
            ]
    
    def quarantine_test(self, test_id: str) -> bool:
        """Mark a test as quarantined."""
        with self.get_session() as session:
            flaky = session.query(FlakyTest).filter(FlakyTest.test_id == test_id).first()
            if flaky:
                flaky.is_quarantined = True
                flaky.quarantined_at = datetime.utcnow()
                return True
            return False
    
    # ===== Pipeline Run Operations =====
    
    def create_pipeline_run(self, run_data: Dict[str, Any]) -> int:
        """Create a new pipeline run record."""
        with self.get_session() as session:
            run = PipelineRun(
                run_id=run_data.get("run_id"),
                trigger=run_data.get("trigger", "manual"),
                branch=run_data.get("branch", "main"),
                commit_sha=run_data.get("commit_sha", ""),
                status=run_data.get("status", "pending"),
                extra_data=run_data.get("metadata", {}),
            )
            session.add(run)
            session.flush()
            return run.id
    
    def complete_pipeline_run(self, run_id: str, results: Dict[str, Any]) -> bool:
        """Update pipeline run with completion results."""
        with self.get_session() as session:
            run = session.query(PipelineRun).filter(PipelineRun.run_id == run_id).first()
            if run:
                run.status = results.get("status", "completed")
                run.completed_at = datetime.utcnow()
                run.vulnerabilities_found = results.get("vulnerabilities_found", 0)
                run.flaky_tests_detected = results.get("flaky_tests_detected", 0)
                run.tests_impacted = results.get("tests_impacted", 0)
                run.decision = results.get("decision", "review")
                if run.started_at and run.completed_at:
                    run.duration_seconds = (run.completed_at - run.started_at).total_seconds()
                return True
            return False
    
    def get_pipeline_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent pipeline runs."""
        with self.get_session() as session:
            runs = session.query(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(limit).all()
            return [
                {
                    "id": r.id,
                    "run_id": r.run_id,
                    "trigger": r.trigger,
                    "branch": r.branch,
                    "status": r.status,
                    "decision": r.decision,
                    "vulnerabilities_found": r.vulnerabilities_found,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "duration_seconds": r.duration_seconds,
                }
                for r in runs
            ]
    
    # ===== Agent State Operations =====
    
    def save_agent_state(self, agent_name: str, session_id: str, key: str, value: Any) -> bool:
        """Save agent state to database."""
        with self.get_session() as session:
            state = session.query(AgentState).filter(
                AgentState.agent_name == agent_name,
                AgentState.session_id == session_id,
                AgentState.state_key == key
            ).first()
            
            if state:
                state.state_value = value
                state.updated_at = datetime.utcnow()
            else:
                state = AgentState(
                    agent_name=agent_name,
                    session_id=session_id,
                    state_key=key,
                    state_value=value,
                )
                session.add(state)
            
            return True
    
    def get_agent_state(self, agent_name: str, session_id: str, key: str) -> Optional[Any]:
        """Get agent state from database."""
        with self.get_session() as session:
            state = session.query(AgentState).filter(
                AgentState.agent_name == agent_name,
                AgentState.session_id == session_id,
                AgentState.state_key == key
            ).first()
            
            return state.state_value if state else None
    
    def get_all_agent_states(self, agent_name: str, session_id: str) -> Dict[str, Any]:
        """Get all state for an agent session."""
        with self.get_session() as session:
            states = session.query(AgentState).filter(
                AgentState.agent_name == agent_name,
                AgentState.session_id == session_id
            ).all()
            
            return {s.state_key: s.state_value for s in states}
    
    # ===== Statistics =====
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get statistics for the dashboard."""
        with self.get_session() as session:
            # Vulnerability stats
            vuln_total = session.query(Vulnerability).count()
            vuln_unfixed = session.query(Vulnerability).filter(Vulnerability.is_fixed == False).count()
            vuln_critical = session.query(Vulnerability).filter(
                Vulnerability.severity == "critical",
                Vulnerability.is_fixed == False
            ).count()
            
            # Flaky test stats
            flaky_total = session.query(FlakyTest).count()
            flaky_quarantined = session.query(FlakyTest).filter(FlakyTest.is_quarantined == True).count()
            
            # Pipeline stats
            pipeline_total = session.query(PipelineRun).count()
            pipeline_success = session.query(PipelineRun).filter(PipelineRun.status == "success").count()
            
            return {
                "vulnerabilities": {
                    "total": vuln_total,
                    "unfixed": vuln_unfixed,
                    "critical": vuln_critical,
                },
                "flaky_tests": {
                    "total": flaky_total,
                    "quarantined": flaky_quarantined,
                },
                "pipelines": {
                    "total": pipeline_total,
                    "success": pipeline_success,
                    "success_rate": (pipeline_success / pipeline_total * 100) if pipeline_total > 0 else 0,
                },
            }


# ===== Convenience Functions =====

def get_db() -> DatabaseManager:
    """Get the database manager singleton."""
    return DatabaseManager()


def init_database(db_url: Optional[str] = None) -> DatabaseManager:
    """Initialize database and create tables."""
    db = DatabaseManager(db_url)
    db.create_tables()
    return db
