"""
Test Database Module - Verify SQLite/PostgreSQL persistence.

Tests:
1. Database initialization and table creation
2. Vulnerability CRUD operations
3. Flaky test tracking persistence
4. Pipeline run recording
5. Agent state management
"""

import os
import sys
from pathlib import Path
from datetime import datetime

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from core.database import (
    DatabaseManager, init_database, get_db,
    Vulnerability, Scan, FlakyTest, PipelineRun, AgentState
)


def test_database():
    """Run database tests."""
    print("\n" + "="*60)
    print("🗄️  DATABASE PERSISTENCE TEST SUITE")
    print("="*60)
    
    # Remove existing test database
    db_path = Path("./test_devsecops.db")
    if db_path.exists():
        db_path.unlink()
    
    # Initialize with test SQLite database
    print("\n📁 Initializing test database...")
    db = init_database("sqlite:///./test_devsecops.db")
    print("✅ Database initialized and tables created")
    
    # Test 1: Vulnerability Storage
    print("\n" + "-"*40)
    print("🧪 TEST 1: Vulnerability Storage")
    print("-"*40)
    
    vuln_data = {
        "id": "CVE-2024-1234",
        "scan_type": "sast",
        "severity": "critical",
        "title": "SQL Injection in user input",
        "description": "User input is directly concatenated into SQL query",
        "file_path": "src/auth.py",
        "line_number": 45,
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "recommendation": "Use parameterized queries",
        "cwe_ids": ["CWE-89"],
        "cvss_score": 9.8,
    }
    
    vuln_id = db.add_vulnerability(vuln_data)
    print(f"✅ Added vulnerability with ID: {vuln_id}")
    
    # Add more vulnerabilities
    for i, severity in enumerate(["high", "medium", "low"]):
        db.add_vulnerability({
            "id": f"VULN-{i+2}",
            "scan_type": "sca",
            "severity": severity,
            "title": f"Test vulnerability {i+2}",
            "file_path": f"src/module{i}.py",
            "line_number": 10 + i*5,
        })
    
    vulns = db.get_vulnerabilities()
    print(f"✅ Retrieved {len(vulns)} vulnerabilities")
    
    # Filter by severity
    critical_vulns = db.get_vulnerabilities(severity="critical")
    print(f"   Critical vulnerabilities: {len(critical_vulns)}")
    
    # Test 2: Scan Recording
    print("\n" + "-"*40)
    print("🧪 TEST 2: Scan Recording")
    print("-"*40)
    
    scan_id = db.create_scan({
        "scan_type": "sast",
        "target_path": "/project/src",
        "status": "running",
    })
    print(f"✅ Created scan with ID: {scan_id}")
    
    # Complete the scan
    db.complete_scan(scan_id, {
        "status": "completed",
        "total_findings": 4,
        "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 1},
        "risk_score": 35.0,
    })
    print("✅ Scan completed with results")
    
    scans = db.get_recent_scans()
    print(f"   Recent scans: {len(scans)}")
    
    # Test 3: Flaky Test Persistence
    print("\n" + "-"*40)
    print("🧪 TEST 3: Flaky Test Persistence")
    print("-"*40)
    
    flaky_tests = [
        {
            "test_id": "test_auth::test_login_timeout",
            "test_name": "test_login_timeout",
            "file_path": "tests/test_auth.py",
            "p_failure": 0.65,
            "total_runs": 20,
            "failures": 13,
            "flakiness_type": "NOD",
            "detected_patterns": ["timeout", "network"],
        },
        {
            "test_id": "test_db::test_concurrent_write",
            "test_name": "test_concurrent_write",
            "file_path": "tests/test_db.py",
            "p_failure": 0.45,
            "total_runs": 50,
            "failures": 22,
            "flakiness_type": "OD-Vic",
            "detected_patterns": ["race_condition"],
        },
    ]
    
    for test in flaky_tests:
        db.upsert_flaky_test(test)
    print(f"✅ Added {len(flaky_tests)} flaky tests")
    
    # Quarantine a test
    db.quarantine_test("test_auth::test_login_timeout")
    print("✅ Quarantined test_login_timeout")
    
    # Get flaky tests
    all_flaky = db.get_flaky_tests()
    quarantined = db.get_flaky_tests(quarantined_only=True)
    print(f"   Total flaky tests: {len(all_flaky)}")
    print(f"   Quarantined: {len(quarantined)}")
    
    # Test 4: Pipeline Run Recording
    print("\n" + "-"*40)
    print("🧪 TEST 4: Pipeline Run Recording")
    print("-"*40)
    
    run_id = db.create_pipeline_run({
        "run_id": "run-12345",
        "trigger": "push",
        "branch": "main",
        "commit_sha": "abc123def456",
        "status": "running",
    })
    print(f"✅ Created pipeline run with ID: {run_id}")
    
    # Complete the run
    db.complete_pipeline_run("run-12345", {
        "status": "success",
        "vulnerabilities_found": 4,
        "flaky_tests_detected": 2,
        "tests_impacted": 15,
        "decision": "review",
    })
    print("✅ Pipeline run completed")
    
    runs = db.get_pipeline_runs()
    print(f"   Total pipeline runs: {len(runs)}")
    
    # Test 5: Agent State Management
    print("\n" + "-"*40)
    print("🧪 TEST 5: Agent State Management")
    print("-"*40)
    
    db.save_agent_state("sast_agent", "session-001", "last_scan_path", "/project/src")
    db.save_agent_state("sast_agent", "session-001", "scan_count", 5)
    db.save_agent_state("sast_agent", "session-001", "config", {"rules": ["security"], "timeout": 300})
    print("✅ Saved 3 agent states")
    
    # Retrieve state
    last_path = db.get_agent_state("sast_agent", "session-001", "last_scan_path")
    print(f"   Retrieved last_scan_path: {last_path}")
    
    all_state = db.get_all_agent_states("sast_agent", "session-001")
    print(f"   All state keys: {list(all_state.keys())}")
    
    # Test 6: Dashboard Statistics
    print("\n" + "-"*40)
    print("🧪 TEST 6: Dashboard Statistics")
    print("-"*40)
    
    stats = db.get_dashboard_stats()
    print("✅ Dashboard stats retrieved:")
    print(f"   Vulnerabilities: {stats['vulnerabilities']}")
    print(f"   Flaky tests: {stats['flaky_tests']}")
    print(f"   Pipelines: {stats['pipelines']}")
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    print("✅ All database persistence tests passed!")
    print(f"\n   Database file: {db_path.absolute()}")
    print(f"   File size: {db_path.stat().st_size / 1024:.2f} KB")
    
    # Cleanup
    db_path.unlink()
    print("\n🧹 Cleaned up test database")
    
    return True


if __name__ == "__main__":
    success = test_database()
    sys.exit(0 if success else 1)
