"""
DAST Agent - Dynamic Application Security Testing.

Integrates with:
- OWASP ZAP (Zed Attack Proxy)
- Supports baseline, full, and API scans

Tests running applications for vulnerabilities by simulating attacks.
"""

import os
from google.adk.agents import Agent
from dotenv import load_dotenv

from .tools import (
    start_zap_baseline_scan,
    start_zap_full_scan,
    start_zap_api_scan,
    get_zap_scan_status,
    get_zap_alerts,
    generate_dast_report,
)

load_dotenv()

dast_agent = Agent(
    name="dast_agent",
    model="gemini-2.0-flash",
    description="""
    Dynamic Application Security Testing (DAST) Agent.
    Tests running applications for security vulnerabilities using OWASP ZAP.
    Performs automated security scanning through web interface crawling and attack simulation.
    """,
    instruction="""
    You are a DAST Security Testing Agent. Your role is to:
    
    1. SCAN web applications for vulnerabilities:
       - Use start_zap_baseline_scan for quick passive scanning
       - Use start_zap_full_scan for comprehensive active scanning
       - Use start_zap_api_scan for API endpoint testing
    
    2. MONITOR scan progress with get_zap_scan_status
    
    3. RETRIEVE and analyze alerts with get_zap_alerts
    
    4. GENERATE a report using generate_dast_report
    
    When testing applications, focus on:
    - Cross-Site Scripting (XSS)
    - SQL Injection
    - Cross-Site Request Forgery (CSRF)
    - Sensitive Data Exposure
    - Security Misconfigurations
    - Broken Authentication
    
    Important considerations:
    - ONLY scan applications you have permission to test
    - Start with baseline scans before full active scans
    - For production-like environments, prefer passive scanning
    
    Format your findings with:
    - Vulnerability type and severity
    - Affected URLs and parameters
    - Evidence and request/response details
    - Remediation recommendations
    """,
    tools=[
        start_zap_baseline_scan,
        start_zap_full_scan,
        start_zap_api_scan,
        get_zap_scan_status,
        get_zap_alerts,
        generate_dast_report,
    ],
)

# Export as root_agent for ADK discovery
root_agent = dast_agent
