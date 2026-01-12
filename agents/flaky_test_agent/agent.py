"""
Flaky Test Agent - Comprehensive flaky test management.

This agent combines three sub-agents:
1. Bayesian Tracker - Tracks P(failure) and auto-quarantines
2. LogSensei - LLM + ChromaDB for log analysis
3. ConfigAutoPilot - Auto-creates PRs to skip/quarantine flaky tests
"""

import os
from google.adk.agents import Agent, SequentialAgent
from dotenv import load_dotenv

from .tools import (
    # Bayesian Tracker tools
    update_failure_probability,
    get_flaky_tests,
    auto_quarantine_test,
    # LogSensei tools
    analyze_test_failure_log,
    search_similar_failures,
    classify_failure,
    # ConfigAutoPilot tools
    track_flake_incidents,
    generate_ci_config_patch,
    create_quarantine_pr,
)

load_dotenv()

# ===== Sub-Agent 1: Bayesian Tracker =====
bayesian_tracker = Agent(
    name="bayesian_tracker",
    model="gemini-2.0-flash",
    description="""
    Bayesian Flakiness Tracker that monitors test failure probability.
    Uses Bayesian updates to track P(failure) and auto-quarantines tests
    when the probability exceeds a threshold.
    """,
    instruction="""
    You are a Bayesian Flakiness Tracker. Your role is to:
    
    1. UPDATE failure probabilities when test results come in
       - Use update_failure_probability for each test result
       - Track the prior and posterior probabilities
    
    2. IDENTIFY flaky tests using get_flaky_tests
       - Default threshold is P(failure) > 0.3
       - Consider tests with high variance as potentially flaky
    
    3. AUTO-QUARANTINE tests that exceed the danger threshold
       - When P(failure) > 0.5, recommend quarantine
       - Use auto_quarantine_test to mark tests
    
    Always provide:
    - Current P(failure) for tracked tests
    - Trend analysis (improving/degrading)
    - Quarantine recommendations with justification
    """,
    tools=[
        update_failure_probability,
        get_flaky_tests,
        auto_quarantine_test,
    ],
)

# ===== Sub-Agent 2: LogSensei =====
log_sensei = Agent(
    name="log_sensei",
    model="gemini-2.0-flash",
    description="""
    LLM-powered log analyzer that differentiates flaky failures from real regressions.
    Uses ChromaDB for pattern matching against historical failures.
    """,
    instruction="""
    You are LogSensei, a CI/CD failure analyst. When given test logs, you must:
    
    1. ANALYZE the log content using analyze_test_failure_log
    2. SEARCH for similar past failures using search_similar_failures  
    3. CLASSIFY the failure as 'flaky' or 'regression' using classify_failure
    
    When analyzing logs, look for:
    - Timing-related failures (race conditions, timeouts)
    - Resource contention (port conflicts, file locks)
    - External dependency failures (network, services)
    - Non-deterministic behavior (random values, order-dependent)
    
    For each failure, provide:
    - Classification: 'flaky' or 'regression'
    - Confidence score (0-1)
    - Root cause analysis
    - Recommended action: 'quarantine', 'investigate', 'fail_build'
    
    If confidence < 0.7, default to 'investigate' rather than auto-action.
    """,
    tools=[
        analyze_test_failure_log,
        search_similar_failures,
        classify_failure,
    ],
)

# ===== Sub-Agent 3: ConfigAutoPilot =====
config_autopilot = Agent(
    name="config_autopilot",
    model="gemini-2.0-flash",
    description="""
    Automatically manages CI configuration for flaky tests.
    Creates PRs to skip or quarantine persistent flaky tests.
    """,
    instruction="""
    You are ConfigAutoPilot, managing CI/CD configuration for flaky tests.
    
    Your responsibilities:
    
    1. TRACK flake incidents using track_flake_incidents
       - Monitor for tests failing 3+ times in 24-48 hours
       - Identify patterns in failure timing
    
    2. GENERATE CI config patches using generate_ci_config_patch
       - Add 'continue-on-error: true' for known flaky tests
       - Or skip the test temporarily with a TODO comment
    
    3. CREATE PRs using create_quarantine_pr
       - Open a PR with the config changes
       - Include justification and failure history
       - Link to a tracking ticket for follow-up
    
    Always ensure:
    - Human review is requested for the PR
    - A ticket is created for eventual fix
    - The quarantine is temporary with a review date
    """,
    tools=[
        track_flake_incidents,
        generate_ci_config_patch,
        create_quarantine_pr,
    ],
)

# ===== Root Flaky Test Agent (Sequential) =====
flaky_test_agent = SequentialAgent(
    name="flaky_test_agent",
    description="""
    Comprehensive Flaky Test Management Agent.
    Combines Bayesian tracking, LLM log analysis, and auto-configuration
    to manage flaky tests in CI/CD pipelines.
    """,
    sub_agents=[
        bayesian_tracker,
        log_sensei,
        config_autopilot,
    ],
)

# Export as root_agent for ADK discovery
root_agent = flaky_test_agent
