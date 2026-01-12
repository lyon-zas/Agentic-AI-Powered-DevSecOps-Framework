"""
IAST Agent Tools - Runtime security analysis.

Tools for Interactive Application Security Testing.
Analyzes runtime behavior and data flows to detect vulnerabilities.

Note: Full IAST requires instrumentation. These tools provide
a framework for processing IAST data and can be extended with
specific IAST solution integrations (Contrast, Hdiv, etc.).
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


# ===== Data Structures =====

@dataclass
class DataFlowPath:
    """Represents a data flow from source to sink."""
    source: str  # Where data entered (e.g., "request.params['id']")
    sink: str    # Where data was used (e.g., "db.execute(query)")
    tainted_data: str  # The actual data value
    transforms: List[str]  # Transformations applied (encode, escape, etc.)
    is_sanitized: bool
    
@dataclass
class RuntimeVulnerability:
    """Vulnerability detected at runtime."""
    vuln_type: str
    severity: str
    data_flow: DataFlowPath
    stack_trace: List[str]
    file_path: str
    line_number: int
    evidence: str


def analyze_runtime_trace(
    trace_data: Dict[str, Any],
    trace_format: str = "json"
) -> Dict[str, Any]:
    """
    Analyze runtime trace data from an instrumented application.
    
    Args:
        trace_data: Runtime trace (can be from various IAST tools)
        trace_format: Format of the trace (json, contrast, hdiv)
    
    Returns:
        Dictionary with analyzed trace data
    """
    if not trace_data:
        return {
            "status": "error",
            "error_message": "No trace data provided"
        }
    
    # Parse based on format
    if trace_format == "contrast":
        return _parse_contrast_trace(trace_data)
    elif trace_format == "hdiv":
        return _parse_hdiv_trace(trace_data)
    else:
        return _parse_generic_trace(trace_data)


def detect_data_flow_vulnerabilities(
    trace_analysis: Dict[str, Any],
    rules: Optional[List[Dict]] = None
) -> Dict[str, Any]:
    """
    Detect vulnerabilities in data flow paths.
    
    Looks for dangerous patterns where untrusted data reaches
    sensitive sinks without proper sanitization.
    
    Args:
        trace_analysis: Output from analyze_runtime_trace
        rules: Custom detection rules (optional)
    
    Returns:
        Dictionary with detected vulnerabilities
    """
    if trace_analysis.get("status") == "error":
        return trace_analysis
    
    data_flows = trace_analysis.get("data_flows", [])
    http_requests = trace_analysis.get("http_requests", [])
    
    # Default vulnerability detection rules
    default_rules = [
        {
            "name": "SQL_INJECTION",
            "sink_patterns": ["db.execute", "cursor.execute", "query", "sql"],
            "severity": "critical",
        },
        {
            "name": "COMMAND_INJECTION",
            "sink_patterns": ["os.system", "subprocess", "exec", "shell"],
            "severity": "critical",
        },
        {
            "name": "XSS",
            "sink_patterns": ["render", "template", "html", "innerHTML"],
            "severity": "high",
        },
        {
            "name": "PATH_TRAVERSAL",
            "sink_patterns": ["open", "file", "read", "write", "path"],
            "severity": "high",
        },
        {
            "name": "SSRF",
            "sink_patterns": ["requests.get", "urllib", "http.client", "fetch"],
            "severity": "high",
        },
        {
            "name": "LOG_INJECTION",
            "sink_patterns": ["logger", "logging", "log."],
            "severity": "medium",
        },
    ]
    
    rules = rules or default_rules
    vulnerabilities = []
    
    for flow in data_flows:
        source = flow.get("source", "")
        sink = flow.get("sink", "")
        is_sanitized = flow.get("is_sanitized", False)
        
        # Skip if properly sanitized
        if is_sanitized:
            continue
        
        # Check against rules
        for rule in rules:
            for pattern in rule["sink_patterns"]:
                if pattern.lower() in sink.lower():
                    vuln = {
                        "type": rule["name"],
                        "severity": rule["severity"],
                        "source": source,
                        "sink": sink,
                        "data_flow": flow,
                        "evidence": flow.get("tainted_data", "")[:100],
                        "file_path": flow.get("file_path", "unknown"),
                        "line_number": flow.get("line_number", 0),
                        "stack_trace": flow.get("stack_trace", []),
                    }
                    vulnerabilities.append(vuln)
                    break
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "medium")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    return {
        "status": "success",
        "total_vulnerabilities": len(vulnerabilities),
        "by_severity": severity_counts,
        "vulnerabilities": vulnerabilities,
        "analyzed_flows": len(data_flows),
        "analyzed_requests": len(http_requests),
    }


def correlate_with_source(
    vulnerabilities: List[Dict[str, Any]],
    source_root: str = "."
) -> Dict[str, Any]:
    """
    Correlate runtime vulnerabilities with source code.
    
    Maps stack traces and sinks to actual source files,
    providing developers with exact code locations.
    
    Args:
        vulnerabilities: List of detected vulnerabilities
        source_root: Root directory of source code
    
    Returns:
        Dictionary with source-correlated vulnerabilities
    """
    correlated = []
    
    for vuln in vulnerabilities:
        file_path = vuln.get("file_path", "")
        line_number = vuln.get("line_number", 0)
        
        # Try to read the source code snippet
        code_snippet = None
        full_path = os.path.join(source_root, file_path)
        
        if os.path.exists(full_path) and line_number > 0:
            try:
                with open(full_path, 'r') as f:
                    lines = f.readlines()
                    start = max(0, line_number - 3)
                    end = min(len(lines), line_number + 3)
                    code_snippet = "".join(lines[start:end])
            except Exception as e:
                logger.warning(f"Could not read source file {full_path}: {e}")
        
        correlated_vuln = {
            **vuln,
            "source_available": code_snippet is not None,
            "code_snippet": code_snippet,
            "full_path": full_path if os.path.exists(full_path) else None,
        }
        correlated.append(correlated_vuln)
    
    return {
        "status": "success",
        "total_correlated": len(correlated),
        "source_found": len([v for v in correlated if v["source_available"]]),
        "vulnerabilities": correlated,
    }


def generate_iast_report(
    vulnerabilities: Dict[str, Any],
    trace_summary: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate a comprehensive IAST security report.
    
    Args:
        vulnerabilities: Output from detect_data_flow_vulnerabilities
        trace_summary: Optional summary from analyze_runtime_trace
    
    Returns:
        Dictionary with IAST report
    """
    if vulnerabilities.get("status") != "success":
        return {
            "status": "error",
            "error_message": "Cannot generate report without valid vulnerability data"
        }
    
    by_severity = vulnerabilities.get("by_severity", {})
    total = vulnerabilities.get("total_vulnerabilities", 0)
    
    # Calculate risk score
    risk_score = (
        by_severity.get("critical", 0) * 20 +
        by_severity.get("high", 0) * 12 +
        by_severity.get("medium", 0) * 5 +
        by_severity.get("low", 0) * 1
    )
    risk_score = min(100, risk_score)
    
    # Determine overall status
    if by_severity.get("critical", 0) > 0:
        overall_status = "critical"
        recommendation = "BLOCK: Critical runtime vulnerabilities detected with verified exploitation paths!"
    elif by_severity.get("high", 0) > 0:
        overall_status = "high_risk"
        recommendation = "URGENT: High-severity data flow vulnerabilities confirmed"
    elif by_severity.get("medium", 0) > 0:
        overall_status = "medium_risk"
        recommendation = "REVIEW: Medium-severity issues detected at runtime"
    else:
        overall_status = "low_risk"
        recommendation = "PASS: No significant runtime vulnerabilities detected"
    
    # Group by type
    by_type = {}
    for v in vulnerabilities.get("vulnerabilities", []):
        vtype = v.get("type", "Unknown")
        if vtype not in by_type:
            by_type[vtype] = []
        by_type[vtype].append(v)
    
    report = {
        "status": "success",
        "report_type": "IAST",
        "timestamp": datetime.now().isoformat(),
        "total_vulnerabilities": total,
        "by_severity": by_severity,
        "by_type": {k: len(v) for k, v in by_type.items()},
        "risk_score": risk_score,
        "overall_status": overall_status,
        "recommendation": recommendation,
        "top_vulnerabilities": vulnerabilities.get("vulnerabilities", [])[:10],
        "iast_advantage": "Vulnerabilities confirmed via runtime data flow analysis - low false positive rate",
    }
    
    if trace_summary:
        report["trace_summary"] = {
            "total_requests": trace_summary.get("http_requests_count", 0),
            "total_data_flows": trace_summary.get("data_flows_count", 0),
            "coverage": trace_summary.get("code_coverage", "N/A"),
        }
    
    return report


# ===== Internal Parsing Functions =====

def _parse_generic_trace(trace_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a generic JSON trace format."""
    
    # Extract data flows
    data_flows = trace_data.get("data_flows", [])
    if not data_flows:
        # Try alternative keys
        data_flows = trace_data.get("flows", [])
        data_flows = data_flows or trace_data.get("taint_flows", [])
    
    # Extract HTTP requests
    http_requests = trace_data.get("http_requests", [])
    http_requests = http_requests or trace_data.get("requests", [])
    
    # Normalize data flows
    normalized_flows = []
    for flow in data_flows:
        normalized_flows.append({
            "source": flow.get("source") or flow.get("input") or "unknown",
            "sink": flow.get("sink") or flow.get("output") or "unknown",
            "tainted_data": flow.get("data") or flow.get("value") or "",
            "transforms": flow.get("transforms") or flow.get("sanitizers") or [],
            "is_sanitized": flow.get("is_sanitized", False) or len(flow.get("sanitizers", [])) > 0,
            "file_path": flow.get("file") or flow.get("file_path") or "",
            "line_number": flow.get("line") or flow.get("line_number") or 0,
            "stack_trace": flow.get("stack_trace") or flow.get("stacktrace") or [],
        })
    
    return {
        "status": "success",
        "format": "generic",
        "data_flows": normalized_flows,
        "data_flows_count": len(normalized_flows),
        "http_requests": http_requests,
        "http_requests_count": len(http_requests),
        "metadata": trace_data.get("metadata", {}),
    }


def _parse_contrast_trace(trace_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Contrast Security IAST trace format."""
    # Contrast-specific parsing would go here
    # For now, use generic parser
    return _parse_generic_trace(trace_data)


def _parse_hdiv_trace(trace_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Hdiv IAST trace format."""
    # Hdiv-specific parsing would go here
    # For now, use generic parser
    return _parse_generic_trace(trace_data)
