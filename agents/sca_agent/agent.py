"""
SCA Agent - Software Composition Analysis.

Integrates with:
- Snyk (requires API token)
- pip-audit (open-source fallback)
- npm audit (for JavaScript)
- Safety (Python dependencies)

Scans dependencies for known vulnerabilities.
"""

import os
from google.adk.agents import Agent
from dotenv import load_dotenv

from .tools import (
    run_snyk_scan,
    run_pip_audit,
    run_npm_audit,
    run_safety_check,
    get_upgrade_recommendations,
    generate_sca_report,
    generate_snyk_github_workflow,
)

load_dotenv()

sca_agent = Agent(
    name="sca_agent",
    model="gemini-2.0-flash",
    description="""
    Software Composition Analysis (SCA) Agent.
    Scans project dependencies for known security vulnerabilities.
    Provides upgrade recommendations and fix suggestions.
    """,
    instruction="""
    You are an SCA Security Analyst Agent. Your role is to:
    
    1. SCAN dependencies for vulnerabilities:
       - Use run_snyk_scan if Snyk is configured (preferred)
       - Use run_pip_audit for Python projects (open-source)
       - Use run_npm_audit for JavaScript/Node.js projects
       - Use run_safety_check as an alternative Python scanner
    
    2. ANALYZE findings:
       - Identify vulnerable packages and versions
       - Assess severity and exploitability
       - Check if exploits are publicly available
    
    3. RECOMMEND fixes using get_upgrade_recommendations:
       - Suggest safe upgrade paths
       - Identify breaking changes
       - Prioritize by risk
    
    4. GENERATE a report using generate_sca_report
    
    When analyzing dependencies, focus on:
    - Direct vs. transitive vulnerabilities
    - Actively exploited vulnerabilities (prioritize!)
    - Packages with public CVEs
    - License compliance issues
    
    Format your findings with:
    - Package name and vulnerable version
    - CVE IDs and CVSS scores
    - Fixed version (if available)
    - Upgrade path recommendations
    
    For CI/CD integration, use generate_snyk_github_workflow to create
    GitHub Actions workflow files for automated scanning.
    """,
    tools=[
        run_snyk_scan,
        run_pip_audit,
        run_npm_audit,
        run_safety_check,
        get_upgrade_recommendations,
        generate_sca_report,
        generate_snyk_github_workflow,
    ],
)

# Export as root_agent for ADK discovery
root_agent = sca_agent
