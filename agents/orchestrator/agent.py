"""
DevSecOps Orchestrator Agent - Root agent coordinating all security and test agents.

Architecture:
- Uses ParallelAgent for concurrent security scans
- Uses SequentialAgent for orchestration flow
- Integrates GNN, Flaky Test, and Security agents
"""

import os
from google.adk.agents import Agent, SequentialAgent, ParallelAgent
from google.adk.tools.agent_tool import AgentTool
from dotenv import load_dotenv

# Import sub-agents
from ..gnn_agent.agent import gnn_agent
from ..flaky_test_agent.agent import flaky_test_agent
from ..sast_agent.agent import sast_agent
from ..dast_agent.agent import dast_agent
from ..sca_agent.agent import sca_agent
from ..iast_agent.agent import iast_agent

load_dotenv()

# ===== Remediation Agent =====
remediation_agent = Agent(
    name="remediation_agent",
    model="gemini-2.0-flash",
    description="""
    Security Remediation Agent that generates fix suggestions and patches.
    """,
    instruction="""
    You are a Security Remediation Agent. Your role is to:
    
    1. ANALYZE vulnerability reports from security scans
    2. GENERATE specific remediation suggestions
    3. PROVIDE code patches when possible
    4. PRIORITIZE fixes based on severity and exploitability
    
    For each vulnerability, provide:
    - Clear explanation of the issue
    - Step-by-step fix instructions
    - Code example showing the secure implementation
    - Links to relevant security documentation
    
    Always consider:
    - Business impact of the fix
    - Backward compatibility
    - Testing requirements after fix
    """,
    tools=[],  # Will use LLM capabilities for now
)

# ===== Decision Agent =====
decision_agent = Agent(
    name="decision_agent",
    model="gemini-2.0-flash",
    description="""
    Decision Agent that determines whether to auto-approve or require human review.
    """,
    instruction="""
    You are a Decision Agent for the DevSecOps pipeline. Your role is to:
    
    1. EVALUATE the combined results from all security and test agents
    2. DECIDE whether changes can be auto-approved or need human review
    
    Auto-approve criteria (all must be true):
    - No critical or high severity vulnerabilities
    - Test impact prediction confidence > 0.8
    - No newly detected flaky tests
    - Code coverage maintained or improved
    
    Require human review if:
    - Any critical vulnerabilities detected
    - Confidence scores below threshold
    - Breaking changes detected
    - Security policy violations
    
    Provide a clear APPROVE or REVIEW decision with justification.
    """,
    tools=[],  # Decision based on LLM analysis
)

# ===== Security Scanner Parallel Agent =====
security_scanner_agent = ParallelAgent(
    name="security_scanner",
    description="""
    Parallel agent running all security scanning tools concurrently:
    - SAST (Static Application Security Testing) via Semgrep/SonarCloud
    - DAST (Dynamic Application Security Testing) via OWASP ZAP
    - SCA (Software Composition Analysis) via Snyk/pip-audit
    - IAST (Interactive Application Security Testing) for runtime analysis
    """,
    sub_agents=[
        sast_agent,
        dast_agent,
        sca_agent,
        iast_agent,
    ],
)

# ===== Test Intelligence Parallel Agent =====
test_intelligence_agent = ParallelAgent(
    name="test_intelligence",
    description="""
    Parallel agent running test intelligence tasks:
    - GNN-based test impact prediction
    - Flaky test detection and management
    """,
    sub_agents=[
        gnn_agent,
        flaky_test_agent,
    ],
)

# ===== Root Orchestrator Agent =====
devsecops_orchestrator = SequentialAgent(
    name="devsecops_orchestrator",
    description="""
    Root DevSecOps Orchestrator that coordinates all security and testing agents.
    
    Pipeline flow:
    1. Security scans (parallel): SAST, DAST, SCA, IAST
    2. Test intelligence (parallel): GNN prediction, Flaky test management
    3. Remediation: Generate fix suggestions
    4. Decision: Approve or require human review
    """,
    sub_agents=[
        security_scanner_agent,  # Parallel: SAST + DAST + SCA + IAST
        test_intelligence_agent,  # Parallel: GNN + Flaky Test
        remediation_agent,        # Sequential: Generate fixes
        decision_agent,           # Sequential: Approve/Review decision
    ],
)

# Export as root_agent for ADK discovery
root_agent = devsecops_orchestrator

