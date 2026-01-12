"""
SAST Agent - Static Application Security Testing.

Integrates with:
- Semgrep (open-source, runs locally)
- SonarCloud (optional, requires API token)

Detects vulnerabilities through static code analysis without executing the code.
"""

import os
from google.adk.agents import Agent
from dotenv import load_dotenv

from .tools import (
    run_semgrep_scan,
    parse_semgrep_results,
    run_sonarcloud_scan,
    get_sonarcloud_issues,
    generate_sast_report,
)

load_dotenv()

sast_agent = Agent(
    name="sast_agent",
    model="gemini-2.0-flash",
    description="""
    Static Application Security Testing (SAST) Agent.
    Analyzes source code for security vulnerabilities without executing it.
    Uses Semgrep for local scanning and optionally SonarCloud for cloud-based analysis.
    """,
    instruction="""
    You are a SAST Security Analyst Agent. Your role is to:
    
    1. SCAN source code for vulnerabilities using the available tools:
       - Use run_semgrep_scan for fast, local scanning
       - Use run_sonarcloud_scan if SonarCloud is configured
    
    2. ANALYZE the results:
       - Parse findings from each tool
       - Identify patterns and common issues
       - Prioritize by severity (critical > high > medium > low)
    
    3. GENERATE a comprehensive report using generate_sast_report:
       - List all vulnerabilities found
       - Provide CWE IDs where available
       - Include remediation guidance
    
    When analyzing code, focus on:
    - Injection vulnerabilities (SQL, Command, XSS)
    - Authentication/Authorization flaws
    - Sensitive data exposure
    - Insecure configurations
    - Cryptographic issues
    
    Format your findings as a structured VulnerabilityReport with:
    - Total count by severity
    - File locations and line numbers
    - Specific remediation steps
    
    If no vulnerabilities are found, confirm the code passed SAST analysis.
    """,
    tools=[
        run_semgrep_scan,
        parse_semgrep_results,
        run_sonarcloud_scan,
        get_sonarcloud_issues,
        generate_sast_report,
    ],
)

# Export as root_agent for ADK discovery
root_agent = sast_agent
