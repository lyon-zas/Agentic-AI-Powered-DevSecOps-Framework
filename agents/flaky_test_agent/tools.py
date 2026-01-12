"""
Flaky Test Agent Tools - Tools for all three sub-agents.

Includes:
- Bayesian Tracker tools (update_failure_probability, get_flaky_tests, auto_quarantine_test)
- LogSensei tools (analyze_test_failure_log, search_similar_failures, classify_failure)
- ConfigAutoPilot tools (track_flake_incidents, generate_ci_config_patch, create_quarantine_pr)
"""

import os
import json
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# ===== In-Memory Storage (would be replaced with database in production) =====

_test_histories: Dict[str, Dict] = {}  # test_id -> {successes, failures, probability, history}
_quarantined_tests: Dict[str, Dict] = {}  # test_id -> {reason, timestamp, ticket_id}
_flake_incidents: Dict[str, List[Dict]] = {}  # test_id -> [{timestamp, log_hash}]


# ===== Bayesian Tracker Tools =====

def update_failure_probability(
    test_id: str,
    test_name: str,
    passed: bool,
    prior_alpha: float = 1.0,
    prior_beta: float = 1.0
) -> Dict[str, Any]:
    """
    Update the failure probability for a test using Bayesian inference.
    
    Uses a Beta-Binomial model:
    - Prior: Beta(alpha, beta) - default is uniform Beta(1,1)
    - Posterior: Beta(alpha + failures, beta + successes)
    - P(failure) = alpha / (alpha + beta)
    
    Args:
        test_id: Unique test identifier
        test_name: Human-readable test name
        passed: Whether the test passed
        prior_alpha: Prior alpha (failures)
        prior_beta: Prior beta (successes)
    
    Returns:
        Dictionary with updated probability and statistics
    """
    if test_id not in _test_histories:
        _test_histories[test_id] = {
            "test_name": test_name,
            "alpha": prior_alpha,  # failures + prior
            "beta": prior_beta,    # successes + prior
            "total_runs": 0,
            "failures": 0,
            "successes": 0,
            "history": [],
            "created_at": datetime.now().isoformat(),
        }
    
    record = _test_histories[test_id]
    record["total_runs"] += 1
    
    if passed:
        record["successes"] += 1
        record["beta"] += 1
    else:
        record["failures"] += 1
        record["alpha"] += 1
    
    # Calculate posterior probability of failure
    p_failure = record["alpha"] / (record["alpha"] + record["beta"])
    
    # Store in history
    record["history"].append({
        "timestamp": datetime.now().isoformat(),
        "passed": passed,
        "p_failure": p_failure,
    })
    
    # Keep only last 100 history entries
    if len(record["history"]) > 100:
        record["history"] = record["history"][-100:]
    
    # Calculate trend (is it getting worse?)
    trend = "stable"
    if len(record["history"]) >= 5:
        recent_5 = [h["p_failure"] for h in record["history"][-5:]]
        older_5 = [h["p_failure"] for h in record["history"][-10:-5]] if len(record["history"]) >= 10 else []
        
        if older_5:
            recent_avg = sum(recent_5) / len(recent_5)
            older_avg = sum(older_5) / len(older_5)
            if recent_avg > older_avg + 0.1:
                trend = "degrading"
            elif recent_avg < older_avg - 0.1:
                trend = "improving"
    
    return {
        "status": "success",
        "test_id": test_id,
        "test_name": test_name,
        "p_failure": round(p_failure, 4),
        "total_runs": record["total_runs"],
        "failures": record["failures"],
        "successes": record["successes"],
        "failure_rate": round(record["failures"] / record["total_runs"], 4),
        "trend": trend,
        "is_flaky": p_failure > 0.3 and record["total_runs"] >= 5,
        "should_quarantine": p_failure > 0.5 and record["total_runs"] >= 10,
    }


def get_flaky_tests(threshold: float = 0.3, min_runs: int = 5) -> Dict[str, Any]:
    """
    Get all tests that are considered flaky based on failure probability.
    
    Args:
        threshold: P(failure) threshold to consider a test flaky
        min_runs: Minimum runs required before classifying
    
    Returns:
        Dictionary with list of flaky tests and statistics
    """
    flaky_tests = []
    all_tests = []
    
    for test_id, record in _test_histories.items():
        p_failure = record["alpha"] / (record["alpha"] + record["beta"])
        
        test_info = {
            "test_id": test_id,
            "test_name": record["test_name"],
            "p_failure": round(p_failure, 4),
            "total_runs": record["total_runs"],
            "failures": record["failures"],
            "is_quarantined": test_id in _quarantined_tests,
        }
        
        all_tests.append(test_info)
        
        if p_failure > threshold and record["total_runs"] >= min_runs:
            flaky_tests.append(test_info)
    
    # Sort by failure probability (highest first)
    flaky_tests.sort(key=lambda x: x["p_failure"], reverse=True)
    
    return {
        "status": "success",
        "flaky_tests": flaky_tests,
        "total_flaky": len(flaky_tests),
        "total_tracked": len(all_tests),
        "threshold": threshold,
        "min_runs": min_runs,
        "quarantined_count": len(_quarantined_tests),
    }


def auto_quarantine_test(
    test_id: str,
    reason: str,
    create_ticket: bool = True
) -> Dict[str, Any]:
    """
    Automatically quarantine a flaky test.
    
    Args:
        test_id: Test identifier to quarantine
        reason: Reason for quarantine
        create_ticket: Whether to create a tracking ticket
    
    Returns:
        Dictionary with quarantine status
    """
    if test_id not in _test_histories:
        return {
            "status": "error",
            "error_message": f"Test {test_id} not found in tracking history"
        }
    
    record = _test_histories[test_id]
    ticket_id = f"FLAKY-{int(time.time())}" if create_ticket else None
    
    _quarantined_tests[test_id] = {
        "test_name": record["test_name"],
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
        "ticket_id": ticket_id,
        "p_failure_at_quarantine": record["alpha"] / (record["alpha"] + record["beta"]),
        "review_date": (datetime.now() + timedelta(days=7)).isoformat(),
    }
    
    return {
        "status": "success",
        "test_id": test_id,
        "test_name": record["test_name"],
        "quarantined": True,
        "ticket_id": ticket_id,
        "reason": reason,
        "review_date": _quarantined_tests[test_id]["review_date"],
        "message": f"Test {record['test_name']} has been quarantined. Ticket: {ticket_id}"
    }


# ===== LogSensei Tools =====

def analyze_test_failure_log(
    log_content: str,
    test_name: str
) -> Dict[str, Any]:
    """
    Analyze a test failure log to identify root cause indicators.
    
    Looks for common flaky patterns:
    - Timing/timeout issues
    - Resource contention
    - Network failures
    - Non-deterministic behavior
    
    Args:
        log_content: The test failure log
        test_name: Name of the failing test
    
    Returns:
        Dictionary with analysis results
    """
    # Pattern matching for common flaky indicators
    flaky_patterns = {
        "timeout": [
            r"timeout", r"timed out", r"deadline exceeded",
            r"connection timed out", r"read timeout"
        ],
        "race_condition": [
            r"race condition", r"concurrent", r"thread",
            r"deadlock", r"already in use"
        ],
        "resource_contention": [
            r"address already in use", r"port \d+ in use",
            r"file.*locked", r"resource busy", r"EADDRINUSE"
        ],
        "network": [
            r"connection refused", r"network unreachable",
            r"connection reset", r"ECONNREFUSED", r"DNS"
        ],
        "external_service": [
            r"service unavailable", r"503", r"502",
            r"external.*failed", r"api.*error"
        ],
        "non_deterministic": [
            r"random", r"uuid", r"timestamp mismatch",
            r"order.*different", r"flaky"
        ],
    }
    
    log_lower = log_content.lower()
    detected_patterns = []
    flakiness_score = 0
    
    import re
    for category, patterns in flaky_patterns.items():
        for pattern in patterns:
            if re.search(pattern, log_lower, re.IGNORECASE):
                detected_patterns.append({
                    "category": category,
                    "pattern": pattern,
                })
                flakiness_score += 1
                break  # Only count each category once
    
    # Normalize score to 0-1
    max_categories = len(flaky_patterns)
    normalized_score = min(flakiness_score / max_categories, 1.0)
    
    # Determine preliminary classification
    if normalized_score > 0.5:
        preliminary_classification = "likely_flaky"
    elif normalized_score > 0.2:
        preliminary_classification = "possibly_flaky"
    else:
        preliminary_classification = "likely_regression"
    
    return {
        "status": "success",
        "test_name": test_name,
        "log_length": len(log_content),
        "detected_patterns": detected_patterns,
        "pattern_count": len(detected_patterns),
        "flakiness_score": round(normalized_score, 3),
        "preliminary_classification": preliminary_classification,
        "categories_detected": [p["category"] for p in detected_patterns],
    }


def search_similar_failures(
    log_content: str,
    test_name: str,
    n_results: int = 5
) -> Dict[str, Any]:
    """
    Search for similar past failures using vector similarity.
    
    Args:
        log_content: Current failure log
        test_name: Name of the failing test
        n_results: Number of similar results to return
    
    Returns:
        Dictionary with similar failures and their classifications
    """
    # This would integrate with VectorStore in production
    # For now, return mock data structure
    
    # In production:
    # from core.vector_store import VectorStore
    # store = VectorStore()
    # results = store.search_similar_failures(log_content, n_results)
    
    return {
        "status": "success",
        "test_name": test_name,
        "similar_failures": [],  # Would contain actual matches
        "match_count": 0,
        "flaky_match_percentage": 0.0,
        "message": "Vector search not yet connected. Using pattern matching only."
    }


def classify_failure(
    test_name: str,
    log_analysis: Dict[str, Any],
    similar_failures: Dict[str, Any],
    confidence_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Final classification of a test failure as flaky or regression.
    
    Combines pattern analysis and similarity search results.
    
    Args:
        test_name: Name of the failing test
        log_analysis: Output from analyze_test_failure_log
        similar_failures: Output from search_similar_failures
        confidence_threshold: Minimum confidence for auto-action
    
    Returns:
        Dictionary with final classification and recommended action
    """
    flakiness_score = log_analysis.get("flakiness_score", 0)
    pattern_count = log_analysis.get("pattern_count", 0)
    flaky_match_pct = similar_failures.get("flaky_match_percentage", 0)
    patterns_detected = log_analysis.get("categories_detected", [])
    
    # Improved classification logic:
    # If ANY known flaky pattern is detected, lean towards flaky
    # Confidence scales with number of patterns detected
    
    if pattern_count >= 2:
        # Multiple flaky patterns = high confidence flaky
        classification = "flaky"
        confidence = 0.85 + (pattern_count - 2) * 0.05  # Up to 0.95 for 4+ patterns
        confidence = min(confidence, 0.95)
    elif pattern_count == 1:
        # Single flaky pattern = likely flaky, verify with historical data
        if flaky_match_pct > 0.5:
            classification = "flaky"
            confidence = 0.75
        else:
            classification = "possibly_flaky"
            confidence = 0.6
    else:
        # No flaky patterns detected
        if flaky_match_pct > 0.7:
            # Historical data suggests flaky
            classification = "possibly_flaky"
            confidence = flaky_match_pct
        else:
            # No indicators = likely regression
            classification = "regression"
            confidence = 0.9 - flaky_match_pct  # Lower confidence if some historical matches
    
    # Recommended action based on classification
    if classification == "flaky":
        if confidence >= confidence_threshold:
            recommended_action = "quarantine"
            build_action = "continue"
        else:
            recommended_action = "investigate"
            build_action = "continue_with_warning"
    elif classification == "possibly_flaky":
        recommended_action = "investigate"
        build_action = "continue_with_warning"
    else:  # regression
        recommended_action = "fail_build"
        build_action = "fail"
    
    return {
        "status": "success",
        "test_name": test_name,
        "classification": classification,
        "confidence": round(confidence, 3),
        "flakiness_score": round(flakiness_score, 3),
        "pattern_count": pattern_count,
        "recommended_action": recommended_action,
        "build_action": build_action,
        "patterns_detected": patterns_detected,
        "reasoning": _generate_reasoning(classification, log_analysis, confidence),
    }


def _generate_reasoning(classification: str, log_analysis: Dict, confidence: float) -> str:
    """Generate human-readable reasoning for the classification."""
    patterns = log_analysis.get("categories_detected", [])
    
    if classification == "flaky":
        if "timeout" in patterns:
            return f"High confidence ({confidence:.0%}) flaky: Timeout patterns detected. Likely timing-dependent failure."
        elif "race_condition" in patterns:
            return f"High confidence ({confidence:.0%}) flaky: Race condition indicators found. Non-deterministic behavior likely."
        elif "resource_contention" in patterns:
            return f"High confidence ({confidence:.0%}) flaky: Resource contention detected (ports/files). Environment-dependent failure."
        else:
            return f"High confidence ({confidence:.0%}) flaky: Multiple flaky patterns detected in log."
    elif classification == "regression":
        return f"Likely regression ({confidence:.0%}): No common flaky patterns found. Investigate as potential real bug."
    else:
        return f"Uncertain ({confidence:.0%}): Some flaky indicators present but confidence is low. Manual review recommended."


# ===== ConfigAutoPilot Tools =====

def track_flake_incidents(
    test_id: str,
    test_name: str,
    failure_timestamp: str,
    window_hours: int = 48
) -> Dict[str, Any]:
    """
    Track flake incidents for a test within a time window.
    
    Args:
        test_id: Test identifier
        test_name: Test name
        failure_timestamp: ISO timestamp of the failure
        window_hours: Time window to check for repeated failures
    
    Returns:
        Dictionary with incident count and action trigger status
    """
    if test_id not in _flake_incidents:
        _flake_incidents[test_id] = []
    
    # Add new incident
    _flake_incidents[test_id].append({
        "timestamp": failure_timestamp,
        "test_name": test_name,
    })
    
    # Filter to window
    cutoff = datetime.now() - timedelta(hours=window_hours)
    recent_incidents = [
        inc for inc in _flake_incidents[test_id]
        if datetime.fromisoformat(inc["timestamp"]) > cutoff
    ]
    _flake_incidents[test_id] = recent_incidents
    
    incident_count = len(recent_incidents)
    trigger_autopilot = incident_count >= 3
    
    return {
        "status": "success",
        "test_id": test_id,
        "test_name": test_name,
        "incident_count": incident_count,
        "window_hours": window_hours,
        "trigger_autopilot": trigger_autopilot,
        "message": f"Test has failed {incident_count} times in last {window_hours} hours" + 
                   (" - triggering ConfigAutoPilot" if trigger_autopilot else "")
    }


def generate_ci_config_patch(
    test_id: str,
    test_name: str,
    ci_config_path: str = ".github/workflows/test.yml",
    action: str = "continue-on-error"
) -> Dict[str, Any]:
    """
    Generate a YAML patch for CI configuration to handle flaky test.
    
    Args:
        test_id: Test identifier
        test_name: Test name
        ci_config_path: Path to CI config file
        action: 'continue-on-error' or 'skip'
    
    Returns:
        Dictionary with the patch content
    """
    timestamp = datetime.now().isoformat()
    review_date = (datetime.now() + timedelta(days=14)).isoformat()[:10]
    
    if action == "continue-on-error":
        patch = f"""
# FLAKY TEST QUARANTINE - Added by ConfigAutoPilot
# Test: {test_name}
# Date: {timestamp}
# Review by: {review_date}
# Related ticket: FLAKY-{int(time.time())}
- name: Run tests (with flaky test handling)
  continue-on-error: true
  env:
    QUARANTINED_TESTS: "{test_name}"
"""
    else:  # skip
        patch = f"""
# FLAKY TEST SKIP - Added by ConfigAutoPilot
# Test: {test_name}  
# Date: {timestamp}
# Review by: {review_date}
# TODO: Remove this skip and fix the flaky test
pytest -k "not {test_name}"
"""
    
    return {
        "status": "success",
        "test_id": test_id,
        "test_name": test_name,
        "ci_config_path": ci_config_path,
        "action": action,
        "patch": patch.strip(),
        "review_date": review_date,
        "message": f"Generated {action} patch for {test_name}"
    }


def create_quarantine_pr(
    test_id: str,
    test_name: str,
    patch_content: str,
    incident_history: Dict[str, Any],
    repo: str = ""
) -> Dict[str, Any]:
    """
    Create a pull request to quarantine a flaky test.
    
    Args:
        test_id: Test identifier
        test_name: Test name
        patch_content: CI config patch to apply
        incident_history: History of flake incidents
        repo: GitHub repository (owner/repo format)
    
    Returns:
        Dictionary with PR creation status
    """
    # In production, this would use GitHub API
    # For now, return the PR structure
    
    repo = repo or os.getenv("GITHUB_REPO", "owner/repo")
    ticket_id = f"FLAKY-{int(time.time())}"
    
    pr_title = f"[AutoPilot] Quarantine flaky test: {test_name}"
    pr_body = f"""## Flaky Test Quarantine

This PR was automatically created by ConfigAutoPilot to quarantine a flaky test.

### Test Information
- **Test Name**: `{test_name}`
- **Test ID**: `{test_id}`
- **Failures in 48h**: {incident_history.get('incident_count', 'N/A')}

### Changes
This PR adds `continue-on-error: true` for the flaky test to prevent it from blocking CI.

### Action Required
1. Review this PR to ensure quarantine is appropriate
2. Track the fix in ticket: {ticket_id}
3. Remove quarantine once the test is fixed

### Auto-Generated Patch
```yaml
{patch_content}
```

---
*This PR was created by the Flaky Test Agent's ConfigAutoPilot.*
"""
    
    return {
        "status": "success",
        "pr_title": pr_title,
        "pr_body": pr_body,
        "repo": repo,
        "ticket_id": ticket_id,
        "branch_name": f"autopilot/quarantine-{test_id[:8]}",
        "message": f"PR ready to create: {pr_title}",
        "note": "GitHub API integration pending - PR content prepared"
    }
