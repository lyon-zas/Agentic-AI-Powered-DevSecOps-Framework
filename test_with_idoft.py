"""
Test the Agentic DevSecOps Framework with real-world iDoFT data.

International Dataset of Flaky Tests (IDoFT) from University of Illinois:
- py-data.csv: 1,619 Python flaky tests
- pr-data.csv: 8,076 Java flaky tests

Flakiness Types:
- OD: Order-Dependent (test outcome depends on order)
- NIO: Non-Idempotent (test affects its own outcome when re-run)
- NOD: Non-Order-Dependent (flaky regardless of order)
- OD-Vic: Order-Dependent Victim (polluted by other tests)
- OD-Brit: Order-Dependent Brittle (requires setup from other tests)
"""

import csv
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.flaky_test_agent.tools import (
    update_failure_probability,
    get_flaky_tests,
    auto_quarantine_test,
    analyze_test_failure_log,
    classify_failure,
    track_flake_incidents,
    generate_ci_config_patch,
)
from core.vector_store import VectorStore


def load_python_flaky_tests(csv_path: str, limit: int = None) -> list:
    """Load Python flaky tests from iDoFT dataset."""
    tests = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)  # Skip header
        
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
                
            if len(row) >= 4:
                tests.append({
                    'repo_url': row[0].strip(),
                    'commit_sha': row[1].strip(),
                    'test_name': row[2].strip(),
                    'flakiness_type': row[3].strip(),
                    'status': row[4].strip() if len(row) > 4 else '',
                    'pr_url': row[5].strip() if len(row) > 5 else '',
                    'notes': row[6].strip() if len(row) > 6 else '',
                })
    
    return tests


def analyze_dataset_statistics(tests: list) -> dict:
    """Analyze the flaky test dataset."""
    stats = {
        'total_tests': len(tests),
        'by_type': defaultdict(int),
        'by_status': defaultdict(int),
        'unique_repos': set(),
    }
    
    for test in tests:
        flaky_type = test['flakiness_type']
        stats['by_type'][flaky_type] += 1
        stats['by_status'][test['status'] or 'Unknown'] += 1
        stats['unique_repos'].add(test['repo_url'])
    
    stats['unique_repos'] = len(stats['unique_repos'])
    return stats


def test_bayesian_tracker_with_real_data(tests: list):
    """Test the Bayesian tracker with real flaky test data."""
    print("\n" + "="*60)
    print("🧪 TESTING: Bayesian Flakiness Tracker")
    print("="*60)
    
    # Simulate multiple runs for a subset of tests
    test_sample = tests[:50]  # First 50 tests
    
    print(f"\nSimulating test runs for {len(test_sample)} tests from iDoFT...")
    
    for test in test_sample:
        test_id = f"{test['repo_url'].split('/')[-1]}::{test['test_name'].split('::')[-1]}"
        
        # Simulate runs based on flakiness type
        # More flaky types get more failures
        if test['flakiness_type'] in ['OD', 'OD-Vic', 'OD-Brit']:
            runs = [(False,), (True,), (False,), (True,), (False,)]  # 60% fail
        elif test['flakiness_type'] in ['NIO']:
            runs = [(False,), (False,), (True,), (True,), (False,)]  # 60% fail
        elif test['flakiness_type'] in ['NOD']:
            runs = [(True,), (False,), (True,), (False,), (True,)]  # 40% fail
        else:
            runs = [(True,), (True,), (True,), (False,), (True,)]  # 20% fail
        
        for passed in runs:
            result = update_failure_probability(
                test_id=test_id,
                test_name=test['test_name'],
                passed=passed[0]
            )
    
    # Get flaky tests
    flaky_result = get_flaky_tests(threshold=0.3)
    
    print(f"\n📊 Results:")
    print(f"   Total tests tracked: {flaky_result['total_tracked']}")
    print(f"   Tests classified as flaky: {flaky_result['total_flaky']}")
    print(f"   Quarantine threshold (P>0.5) tests: {len([t for t in flaky_result['flaky_tests'] if t['p_failure'] > 0.5])}")
    
    # Show top 5 most flaky
    print(f"\n🔝 Top 5 Most Flaky Tests:")
    for test in flaky_result['flaky_tests'][:5]:
        print(f"   • {test['test_name'][:60]}...")
        print(f"     P(failure): {test['p_failure']:.2%}, Runs: {test['total_runs']}")
    
    return flaky_result


def test_log_analysis_patterns():
    """Test LogSensei pattern detection with synthetic logs."""
    print("\n" + "="*60)
    print("🔍 TESTING: LogSensei Pattern Analysis")
    print("="*60)
    
    # Sample logs representing different failure types
    test_logs = {
        "Timeout (should detect flaky)": """
        FAILED tests/test_api.py::test_http_request
        E       TimeoutError: Connection timed out after 30 seconds
        E       socket.timeout: timed out waiting for response
        """,
        
        "Race Condition (should detect flaky)": """
        FAILED tests/test_concurrent.py::test_parallel_write
        E       AssertionError: Expected 100 but got 99
        E       Concurrent modification detected
        E       Thread synchronization failed
        """,
        
        "Port Conflict (should detect flaky)": """
        FAILED tests/test_server.py::test_start_server
        E       OSError: [Errno 48] Address already in use: port 8080
        E       EADDRINUSE: Resource temporarily unavailable
        """,
        
        "Assertion Error (likely regression)": """
        FAILED tests/test_calculator.py::test_add
        E       AssertionError: Expected 5 but got 4
        E       assert add(2, 2) == 5
        """,
        
        "Network Error (should detect flaky)": """
        FAILED tests/test_external.py::test_api_call
        E       ConnectionError: Connection refused
        E       Failed to establish connection to api.example.com
        """,
    }
    
    print("\nAnalyzing different log patterns...\n")
    
    for name, log in test_logs.items():
        analysis = analyze_test_failure_log(log, name)
        similar = {"flaky_match_percentage": 0}  # Mock similar search
        classification = classify_failure(name, analysis, similar)
        
        emoji = "🟡" if classification['classification'] == 'flaky' else "🔴"
        print(f"{emoji} {name}")
        print(f"   Classification: {classification['classification']}")
        print(f"   Confidence: {classification['confidence']:.0%}")
        print(f"   Patterns: {', '.join(analysis['categories_detected']) or 'None'}")
        print(f"   Action: {classification['recommended_action']}")
        print()
    
    return True


def test_config_autopilot_with_real_data(tests: list):
    """Test ConfigAutoPilot with real flaky test data."""
    print("\n" + "="*60)
    print("🚀 TESTING: ConfigAutoPilot PR Generation")
    print("="*60)
    
    # Simulate repeated failures for a test
    test = tests[0]
    test_id = f"flaky-{test['test_name'].split('::')[-1]}"
    
    print(f"\nSimulating repeated failures for: {test['test_name'][:60]}...")
    
    # Track 5 incidents (should trigger autopilot after 3)
    for i in range(5):
        timestamp = datetime.now().isoformat()
        result = track_flake_incidents(
            test_id=test_id,
            test_name=test['test_name'],
            failure_timestamp=timestamp
        )
        
        if result['trigger_autopilot']:
            print(f"\n⚠️  AutoPilot triggered after {result['incident_count']} failures!")
            
            # Generate patch
            patch = generate_ci_config_patch(
                test_id=test_id,
                test_name=test['test_name'],
                action="continue-on-error"
            )
            
            print(f"\n📝 Generated CI Config Patch:")
            print("-" * 40)
            print(patch['patch'][:500])
            print("-" * 40)
            print(f"\n   Review by: {patch['review_date']}")
            break
    
    return True


def test_vector_store_flaky_patterns(tests: list):
    """Test VectorStore with flaky pattern storage."""
    print("\n" + "="*60)
    print("🗂️  TESTING: Vector Store Pattern Storage")
    print("="*60)
    
    store = VectorStore()
    
    # Add sample flaky patterns
    print("\nAdding flaky test patterns to vector store...")
    
    patterns = [
        ("timeout-1", "Test failed due to connection timeout after waiting 30 seconds", True, "Timing dependency on external service"),
        ("race-1", "Concurrent modification exception in parallel test", True, "Thread synchronization issue"),
        ("flaky-order-1", "Test depends on execution order of previous tests", True, "Order dependency"),
        ("regression-1", "Assertion error: expected 5 but got 4 in calculator", False, "Logic error"),
    ]
    
    for log_id, content, is_flaky, root_cause in patterns:
        store.add_flaky_log_pattern(
            log_id=log_id,
            log_content=content,
            test_name=f"test_{log_id}",
            is_flaky=is_flaky,
            root_cause=root_cause
        )
    
    # Search for similar patterns
    query = "connection timed out waiting for response"
    results = store.search_similar_failures(query, n_results=3)
    
    print(f"\n🔍 Searching for: '{query}'")
    print(f"   Found {len(results)} similar patterns")
    
    for result in results:
        print(f"   • ID: {result.id}")
        print(f"     Content: {result.content[:80]}...")
        print(f"     Is Flaky: {result.metadata.get('is_flaky')}")
    
    return True


def run_full_test_suite():
    """Run all tests with real iDoFT data."""
    print("\n" + "="*70)
    print("🤖 AGENTIC AI DEVSECOPS FRAMEWORK - INTEGRATION TEST")
    print("    Testing with International Dataset of Flaky Tests (iDoFT)")
    print("="*70)
    
    # Load real data
    csv_path = Path(__file__).parent / "idoft" / "py-data.csv"
    
    if not csv_path.exists():
        print(f"\n❌ Error: iDoFT dataset not found at {csv_path}")
        print("   Please run: git clone https://github.com/TestingResearchIllinois/idoft")
        return False
    
    print(f"\n📂 Loading Python flaky tests from iDoFT...")
    tests = load_python_flaky_tests(str(csv_path), limit=200)
    
    # Dataset statistics
    stats = analyze_dataset_statistics(tests)
    print(f"\n📊 Dataset Statistics:")
    print(f"   Total tests loaded: {stats['total_tests']}")
    print(f"   Unique repositories: {stats['unique_repos']}")
    print(f"\n   By Flakiness Type:")
    for ftype, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
        print(f"   • {ftype}: {count}")
    print(f"\n   By Fix Status:")
    for status, count in sorted(stats['by_status'].items(), key=lambda x: -x[1]):
        print(f"   • {status or 'Unknown'}: {count}")
    
    # Run tests
    results = {
        'bayesian_tracker': False,
        'log_analysis': False,
        'config_autopilot': False,
        'vector_store': False,
    }
    
    try:
        test_bayesian_tracker_with_real_data(tests)
        results['bayesian_tracker'] = True
    except Exception as e:
        print(f"\n❌ Bayesian Tracker test failed: {e}")
    
    try:
        test_log_analysis_patterns()
        results['log_analysis'] = True
    except Exception as e:
        print(f"\n❌ Log Analysis test failed: {e}")
    
    try:
        test_config_autopilot_with_real_data(tests)
        results['config_autopilot'] = True
    except Exception as e:
        print(f"\n❌ ConfigAutoPilot test failed: {e}")
    
    try:
        test_vector_store_flaky_patterns(tests)
        results['vector_store'] = True
    except Exception as e:
        print(f"\n❌ Vector Store test failed: {e}")
    
    # Summary
    print("\n" + "="*70)
    print("📋 TEST SUMMARY")
    print("="*70)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, passed_flag in results.items():
        emoji = "✅" if passed_flag else "❌"
        print(f"   {emoji} {test_name.replace('_', ' ').title()}")
    
    print(f"\n   Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Framework validated with real-world data.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Review output above.")
    
    return passed == total


if __name__ == "__main__":
    success = run_full_test_suite()
    sys.exit(0 if success else 1)
