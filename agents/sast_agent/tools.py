"""
SAST Agent Tools - Semgrep and SonarCloud integration.

Tools for static application security testing.
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


def run_semgrep_scan(
    target_path: str,
    config: str = "auto",
    exclude: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Run Semgrep static analysis on the target path.
    
    Semgrep is an open-source, fast, and lightweight static analysis tool
    that supports many languages and has built-in security rulesets.
    
    Args:
        target_path: Path to scan (file or directory)
        config: Semgrep config (auto, p/python, p/security, etc.)
        exclude: List of patterns to exclude
    
    Returns:
        Dictionary with scan results
    """
    try:
        # Try to find semgrep in the same directory as Python executable
        import sys
        python_dir = os.path.dirname(sys.executable)
        semgrep_path = os.path.join(python_dir, "semgrep")
        
        if not os.path.exists(semgrep_path):
            # Fall back to system semgrep
            semgrep_path = "semgrep"
        
        cmd = [
            semgrep_path, "scan",
            "--config", config,
            "--json",
            "--quiet",
        ]
        
        if exclude:
            for pattern in exclude:
                cmd.extend(["--exclude", pattern])
        
        cmd.append(target_path)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode not in [0, 1]:  # 1 means findings found
            return {
                "status": "error",
                "error_message": result.stderr,
                "findings_count": 0,
            }
        
        try:
            output = json.loads(result.stdout)
            findings = output.get("results", [])
            
            return {
                "status": "success",
                "tool": "semgrep",
                "config": config,
                "target_path": target_path,
                "findings_count": len(findings),
                "findings": findings,
                "errors": output.get("errors", []),
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "error_message": "Failed to parse Semgrep JSON output",
                "raw_output": result.stdout[:1000],
            }
            
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "Semgrep not installed. Install with: pip install semgrep",
            "install_command": "pip install semgrep"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "Semgrep scan timed out after 5 minutes",
        }
    except Exception as e:
        logger.error(f"Semgrep scan error: {e}")
        return {
            "status": "error",
            "error_message": str(e),
        }


def parse_semgrep_results(semgrep_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse Semgrep results into structured vulnerability format.
    
    Args:
        semgrep_output: Raw output from run_semgrep_scan
    
    Returns:
        Dictionary with parsed vulnerabilities
    """
    if semgrep_output.get("status") != "success":
        return semgrep_output
    
    findings = semgrep_output.get("findings", [])
    vulnerabilities = []
    
    severity_map = {
        "ERROR": "high",
        "WARNING": "medium", 
        "INFO": "low",
    }
    
    for finding in findings:
        vuln = {
            "id": finding.get("check_id", "unknown"),
            "type": _extract_vuln_type(finding.get("check_id", "")),
            "severity": severity_map.get(finding.get("extra", {}).get("severity", "WARNING"), "medium"),
            "message": finding.get("extra", {}).get("message", ""),
            "file_path": finding.get("path", ""),
            "start_line": finding.get("start", {}).get("line", 0),
            "end_line": finding.get("end", {}).get("line", 0),
            "code_snippet": finding.get("extra", {}).get("lines", ""),
            "cwe_ids": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
            "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", []),
            "fix": finding.get("extra", {}).get("fix", ""),
            "references": finding.get("extra", {}).get("metadata", {}).get("references", []),
        }
        vulnerabilities.append(vuln)
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    return {
        "status": "success",
        "tool": "semgrep",
        "vulnerabilities": vulnerabilities,
        "total_count": len(vulnerabilities),
        "by_severity": severity_counts,
        "scan_timestamp": datetime.now().isoformat(),
    }


def run_sonarcloud_scan(
    project_key: str,
    organization: str = "",
    token: str = ""
) -> Dict[str, Any]:
    """
    Trigger a SonarCloud scan (requires separate CI setup).
    
    Note: SonarCloud scans are typically triggered via CI/CD pipelines.
    This tool retrieves results from an existing scan.
    
    Args:
        project_key: SonarCloud project key
        organization: SonarCloud organization
        token: SonarCloud API token (or uses SONAR_TOKEN env var)
    
    Returns:
        Dictionary with scan status
    """
    token = token or os.getenv("SONAR_TOKEN", "")
    organization = organization or os.getenv("SONAR_ORG", "")
    
    if not token:
        return {
            "status": "skipped",
            "message": "SonarCloud token not configured. Set SONAR_TOKEN env var.",
            "setup_url": "https://sonarcloud.io/account/security"
        }
    
    if not project_key:
        return {
            "status": "error",
            "error_message": "project_key is required"
        }
    
    # Check project status via API
    try:
        url = f"https://sonarcloud.io/api/project_analyses/search"
        params = {"project": project_key}
        
        headers = {"Authorization": f"Bearer {token}"}
        
        with httpx.Client() as client:
            response = client.get(url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            analyses = data.get("analyses", [])
            
            if analyses:
                latest = analyses[0]
                return {
                    "status": "success",
                    "tool": "sonarcloud",
                    "project_key": project_key,
                    "last_analysis_date": latest.get("date"),
                    "revision": latest.get("revision"),
                    "project_version": latest.get("projectVersion"),
                }
            else:
                return {
                    "status": "no_analysis",
                    "message": "No SonarCloud analyses found for this project",
                    "project_key": project_key,
                }
        else:
            return {
                "status": "error",
                "error_message": f"SonarCloud API error: {response.status_code}",
                "response": response.text[:500],
            }
            
    except Exception as e:
        logger.error(f"SonarCloud API error: {e}")
        return {
            "status": "error",
            "error_message": str(e),
        }


def get_sonarcloud_issues(
    project_key: str,
    severities: str = "CRITICAL,MAJOR,BLOCKER",
    token: str = ""
) -> Dict[str, Any]:
    """
    Get security issues from SonarCloud.
    
    Args:
        project_key: SonarCloud project key
        severities: Comma-separated severity levels
        token: SonarCloud API token
    
    Returns:
        Dictionary with security issues
    """
    token = token or os.getenv("SONAR_TOKEN", "")
    
    if not token:
        return {
            "status": "skipped",
            "message": "SonarCloud token not configured"
        }
    
    try:
        url = "https://sonarcloud.io/api/issues/search"
        params = {
            "componentKeys": project_key,
            "severities": severities,
            "types": "VULNERABILITY,SECURITY_HOTSPOT",
            "ps": 100,  # Page size
        }
        
        headers = {"Authorization": f"Bearer {token}"}
        
        with httpx.Client() as client:
            response = client.get(url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            issues = data.get("issues", [])
            
            vulnerabilities = []
            for issue in issues:
                vuln = {
                    "id": issue.get("key"),
                    "type": issue.get("type"),
                    "severity": _map_sonar_severity(issue.get("severity", "MINOR")),
                    "message": issue.get("message"),
                    "file_path": issue.get("component", "").split(":")[-1],
                    "start_line": issue.get("line", 0),
                    "rule": issue.get("rule"),
                    "status": issue.get("status"),
                    "effort": issue.get("effort"),
                }
                vulnerabilities.append(vuln)
            
            return {
                "status": "success",
                "tool": "sonarcloud",
                "project_key": project_key,
                "total_issues": data.get("total", 0),
                "vulnerabilities": vulnerabilities,
                "paging": data.get("paging"),
            }
        else:
            return {
                "status": "error",
                "error_message": f"SonarCloud API error: {response.status_code}",
            }
            
    except Exception as e:
        logger.error(f"SonarCloud issues error: {e}")
        return {
            "status": "error",
            "error_message": str(e),
        }


def generate_sast_report(
    semgrep_results: Dict[str, Any],
    sonarcloud_results: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate a combined SAST report from all tool results.
    
    Args:
        semgrep_results: Output from parse_semgrep_results
        sonarcloud_results: Optional output from get_sonarcloud_issues
    
    Returns:
        Dictionary with combined SAST report
    """
    all_vulnerabilities = []
    sources = []
    
    # Add Semgrep findings
    if semgrep_results.get("status") == "success":
        all_vulnerabilities.extend(semgrep_results.get("vulnerabilities", []))
        sources.append("semgrep")
    
    # Add SonarCloud findings
    if sonarcloud_results and sonarcloud_results.get("status") == "success":
        all_vulnerabilities.extend(sonarcloud_results.get("vulnerabilities", []))
        sources.append("sonarcloud")
    
    # Deduplicate by file+line (rough dedup)
    seen = set()
    unique_vulns = []
    for v in all_vulnerabilities:
        key = f"{v.get('file_path')}:{v.get('start_line')}:{v.get('type')}"
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in unique_vulns:
        sev = v.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Calculate risk score
    risk_score = (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 7 +
        severity_counts["medium"] * 4 +
        severity_counts["low"] * 1
    )
    risk_score = min(100, risk_score)
    
    # Determine overall status
    if severity_counts["critical"] > 0:
        overall_status = "critical"
        recommendation = "BLOCK: Critical vulnerabilities must be fixed before deployment"
    elif severity_counts["high"] > 0:
        overall_status = "high_risk"
        recommendation = "REVIEW: High severity issues require immediate attention"
    elif severity_counts["medium"] > 0:
        overall_status = "medium_risk"
        recommendation = "WARN: Medium severity issues should be addressed soon"
    else:
        overall_status = "low_risk"
        recommendation = "PASS: No critical issues found"
    
    return {
        "status": "success",
        "report_type": "SAST",
        "timestamp": datetime.now().isoformat(),
        "sources": sources,
        "total_vulnerabilities": len(unique_vulns),
        "by_severity": severity_counts,
        "risk_score": risk_score,
        "overall_status": overall_status,
        "recommendation": recommendation,
        "vulnerabilities": unique_vulns,
    }


# ===== Helper Functions =====

def _extract_vuln_type(check_id: str) -> str:
    """Extract vulnerability type from Semgrep check ID."""
    check_lower = check_id.lower()
    
    if "sql" in check_lower:
        return "SQL_INJECTION"
    elif "xss" in check_lower:
        return "CROSS_SITE_SCRIPTING"
    elif "command" in check_lower or "os" in check_lower:
        return "OS_COMMAND_INJECTION"
    elif "path" in check_lower or "traversal" in check_lower:
        return "PATH_TRAVERSAL"
    elif "ssrf" in check_lower:
        return "SSRF"
    elif "crypto" in check_lower or "hash" in check_lower:
        return "INSECURE_CRYPTO"
    elif "auth" in check_lower:
        return "BROKEN_AUTHENTICATION"
    elif "hardcoded" in check_lower or "secret" in check_lower:
        return "HARDCODED_CREDENTIALS"
    elif "deserial" in check_lower:
        return "INSECURE_DESERIALIZATION"
    else:
        return "SECURITY_ISSUE"


def _map_sonar_severity(sonar_severity: str) -> str:
    """Map SonarCloud severity to standard severity."""
    mapping = {
        "BLOCKER": "critical",
        "CRITICAL": "critical",
        "MAJOR": "high",
        "MINOR": "medium",
        "INFO": "low",
    }
    return mapping.get(sonar_severity.upper(), "medium")
