"""
IAST Agent - Interactive Application Security Testing.

IAST combines elements of SAST and DAST by analyzing applications
from within during runtime. It instruments the application to
monitor data flow and detect vulnerabilities in real-time.

Note: Full IAST implementation requires instrumentation agents
(e.g., Contrast Security, Hdiv). This agent provides a framework
for integrating with IAST solutions and analyzing their output.
"""

import os
from google.adk.agents import Agent
from dotenv import load_dotenv

from .tools import (
    analyze_runtime_trace,
    detect_data_flow_vulnerabilities,
    correlate_with_source,
    generate_iast_report,
)

load_dotenv()

iast_agent = Agent(
    name="iast_agent",
    model="gemini-2.0-flash",
    description="""
    Interactive Application Security Testing (IAST) Agent.
    Analyzes application behavior during runtime to detect vulnerabilities.
    Combines static analysis with runtime data flow tracking.
    """,
    instruction="""
    You are an IAST Security Analysis Agent. Your role is to:
    
    1. ANALYZE runtime traces from instrumented applications
       - Use analyze_runtime_trace to process execution data
       - Look for dangerous data flows (tainted inputs reaching sinks)
    
    2. DETECT data flow vulnerabilities:
       - Use detect_data_flow_vulnerabilities to identify:
         - Untrusted data reaching SQL queries
         - User input in command execution
         - Sensitive data in logs
    
    3. CORRELATE findings with source code:
       - Use correlate_with_source to map runtime issues to code
       - Identify the exact vulnerable code paths
    
    4. GENERATE a report using generate_iast_report
    
    IAST advantages over SAST/DAST:
    - Lower false positives (verified at runtime)
    - Precise code location (stack traces available)
    - Data flow visibility (see actual tainted data)
    
    Focus on:
    - Injection vulnerabilities (SQL, Command, XPath)
    - Authentication bypasses
    - Sensitive data exposure
    - Insecure data storage
    - Cryptographic weaknesses
    
    Format findings with:
    - Vulnerability type and severity
    - Data flow path (source → sink)
    - Affected code with stack trace
    - Runtime evidence
    """,
    tools=[
        analyze_runtime_trace,
        detect_data_flow_vulnerabilities,
        correlate_with_source,
        generate_iast_report,
    ],
)

# Export as root_agent for ADK discovery
root_agent = iast_agent
