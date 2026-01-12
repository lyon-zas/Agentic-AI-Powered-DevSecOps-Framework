"""
DAST Agent Tools - OWASP ZAP integration.

Tools for dynamic application security testing using ZAP proxy.
Supports Docker-based ZAP or standalone installation.
"""

import os
import subprocess
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx
import time

logger = logging.getLogger(__name__)

# ZAP API configuration
ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")


def start_zap_baseline_scan(
    target_url: str,
    use_docker: bool = True,
    ajax_spider: bool = False
) -> Dict[str, Any]:
    """
    Start a ZAP baseline scan (passive scanning only).
    
    Baseline scans are quick and safe - they don't actively attack the target.
    Suitable for CI/CD pipelines and production-like environments.
    
    Args:
        target_url: URL of the application to scan
        use_docker: Whether to use Docker to run ZAP
        ajax_spider: Enable AJAX spider for JavaScript-heavy apps
    
    Returns:
        Dictionary with scan initiation status
    """
    if not target_url:
        return {
            "status": "error",
            "error_message": "target_url is required"
        }
    
    if use_docker:
        return _run_zap_docker_scan(target_url, "baseline", ajax_spider)
    else:
        return _start_zap_api_scan_internal(target_url, "baseline", ajax_spider)


def start_zap_full_scan(
    target_url: str,
    use_docker: bool = True,
    ajax_spider: bool = True
) -> Dict[str, Any]:
    """
    Start a ZAP full scan (active scanning).
    
    Full scans actively attack the target to find vulnerabilities.
    WARNING: Only use on applications you own or have explicit permission to test.
    
    Args:
        target_url: URL of the application to scan
        use_docker: Whether to use Docker to run ZAP
        ajax_spider: Enable AJAX spider
    
    Returns:
        Dictionary with scan initiation status
    """
    if not target_url:
        return {
            "status": "error",
            "error_message": "target_url is required"
        }
    
    if use_docker:
        return _run_zap_docker_scan(target_url, "full", ajax_spider)
    else:
        return _start_zap_api_scan_internal(target_url, "full", ajax_spider)


def start_zap_api_scan(
    target_url: str,
    api_spec_url: str = "",
    api_format: str = "openapi",
    use_docker: bool = True
) -> Dict[str, Any]:
    """
    Start a ZAP API scan using OpenAPI/Swagger spec.
    
    Specialized scan for REST APIs that uses the API specification
    to understand and test endpoints.
    
    Args:
        target_url: Base URL of the API
        api_spec_url: URL to OpenAPI/Swagger specification
        api_format: API spec format (openapi, soap)
        use_docker: Whether to use Docker
    
    Returns:
        Dictionary with scan initiation status
    """
    if not target_url:
        return {
            "status": "error",
            "error_message": "target_url is required"
        }
    
    if use_docker:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/zap/wrk:rw",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-api-scan.py",
            "-t", api_spec_url or target_url,
            "-f", api_format,
            "-J", "zap-api-report.json",
            "-r", "zap-api-report.html",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes
            )
            
            return {
                "status": "success" if result.returncode in [0, 1, 2] else "error",
                "scan_type": "api",
                "target_url": target_url,
                "api_spec": api_spec_url,
                "report_file": "zap-api-report.json",
                "exit_code": result.returncode,
                "message": "API scan completed" if result.returncode in [0, 1, 2] else result.stderr,
            }
        except Exception as e:
            return {
                "status": "error",
                "error_message": str(e),
            }
    else:
        return {
            "status": "not_implemented",
            "message": "Non-Docker API scan requires ZAP daemon running"
        }


def get_zap_scan_status(scan_id: str = "") -> Dict[str, Any]:
    """
    Get the status of a running ZAP scan.
    
    Args:
        scan_id: Scan ID (if using ZAP API directly)
    
    Returns:
        Dictionary with scan status
    """
    try:
        # Check if ZAP is running
        with httpx.Client(timeout=5) as client:
            response = client.get(
                f"{ZAP_API_URL}/JSON/core/view/version/",
                params={"apikey": ZAP_API_KEY}
            )
        
        if response.status_code == 200:
            version_data = response.json()
            
            # Get scan progress
            spider_response = client.get(
                f"{ZAP_API_URL}/JSON/spider/view/status/",
                params={"apikey": ZAP_API_KEY}
            )
            
            ascan_response = client.get(
                f"{ZAP_API_URL}/JSON/ascan/view/status/",
                params={"apikey": ZAP_API_KEY}
            )
            
            return {
                "status": "success",
                "zap_running": True,
                "zap_version": version_data.get("version"),
                "spider_progress": spider_response.json().get("status", "0") if spider_response.status_code == 200 else "N/A",
                "active_scan_progress": ascan_response.json().get("status", "0") if ascan_response.status_code == 200 else "N/A",
            }
        else:
            return {
                "status": "error",
                "zap_running": False,
                "message": "ZAP API not responding",
            }
            
    except httpx.ConnectError:
        return {
            "status": "not_running",
            "zap_running": False,
            "message": f"Cannot connect to ZAP at {ZAP_API_URL}. Is ZAP running?",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }


def get_zap_alerts(
    risk_level: str = "all",
    limit: int = 100
) -> Dict[str, Any]:
    """
    Get security alerts from ZAP.
    
    Args:
        risk_level: Filter by risk (all, high, medium, low, informational)
        limit: Maximum number of alerts to return
    
    Returns:
        Dictionary with security alerts
    """
    try:
        params = {"apikey": ZAP_API_KEY}
        
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{ZAP_API_URL}/JSON/core/view/alerts/",
                params=params
            )
        
        if response.status_code == 200:
            data = response.json()
            alerts = data.get("alerts", [])
            
            # Filter by risk level
            if risk_level != "all":
                risk_map = {
                    "high": "High",
                    "medium": "Medium", 
                    "low": "Low",
                    "informational": "Informational"
                }
                filter_risk = risk_map.get(risk_level.lower(), "")
                if filter_risk:
                    alerts = [a for a in alerts if a.get("risk") == filter_risk]
            
            # Limit results
            alerts = alerts[:limit]
            
            # Parse alerts
            parsed_alerts = []
            for alert in alerts:
                parsed_alerts.append({
                    "alert_id": alert.get("id"),
                    "name": alert.get("alert"),
                    "risk": alert.get("risk"),
                    "confidence": alert.get("confidence"),
                    "url": alert.get("url"),
                    "description": alert.get("description"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                    "cwe_id": alert.get("cweid"),
                    "wasc_id": alert.get("wascid"),
                    "evidence": alert.get("evidence", "")[:200],  # Truncate evidence
                })
            
            # Count by risk
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for alert in data.get("alerts", []):
                risk = alert.get("risk", "Informational")
                if risk in risk_counts:
                    risk_counts[risk] += 1
            
            return {
                "status": "success",
                "total_alerts": len(data.get("alerts", [])),
                "filtered_count": len(parsed_alerts),
                "by_risk": risk_counts,
                "alerts": parsed_alerts,
            }
        else:
            return {
                "status": "error",
                "error_message": f"ZAP API error: {response.status_code}",
            }
            
    except httpx.ConnectError:
        return {
            "status": "not_connected",
            "message": "ZAP is not running or not accessible",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }


def generate_dast_report(
    alerts: Dict[str, Any],
    target_url: str = "",
    scan_type: str = "baseline"
) -> Dict[str, Any]:
    """
    Generate a DAST security report from ZAP alerts.
    
    Args:
        alerts: Output from get_zap_alerts
        target_url: URL that was scanned
        scan_type: Type of scan performed
    
    Returns:
        Dictionary with DAST report
    """
    if alerts.get("status") != "success":
        return {
            "status": "error",
            "error_message": "Cannot generate report without valid alerts",
            "input_status": alerts.get("status"),
        }
    
    by_risk = alerts.get("by_risk", {})
    total_alerts = alerts.get("total_alerts", 0)
    
    # Calculate risk score
    risk_score = (
        by_risk.get("High", 0) * 10 +
        by_risk.get("Medium", 0) * 5 +
        by_risk.get("Low", 0) * 2 +
        by_risk.get("Informational", 0) * 0
    )
    risk_score = min(100, risk_score)
    
    # Determine overall status
    if by_risk.get("High", 0) > 0:
        overall_status = "critical"
        recommendation = "BLOCK: High-risk vulnerabilities detected. Do not deploy!"
    elif by_risk.get("Medium", 0) > 0:
        overall_status = "high_risk"
        recommendation = "REVIEW: Medium-risk issues require attention before production"
    elif by_risk.get("Low", 0) > 0:
        overall_status = "medium_risk"
        recommendation = "WARN: Low-risk issues found. Consider fixing soon"
    else:
        overall_status = "low_risk"
        recommendation = "PASS: No significant vulnerabilities detected"
    
    # Group vulnerabilities by type
    vuln_types = {}
    for alert in alerts.get("alerts", []):
        alert_type = alert.get("name", "Unknown")
        if alert_type not in vuln_types:
            vuln_types[alert_type] = []
        vuln_types[alert_type].append(alert)
    
    return {
        "status": "success",
        "report_type": "DAST",
        "timestamp": datetime.now().isoformat(),
        "target_url": target_url,
        "scan_type": scan_type,
        "total_alerts": total_alerts,
        "by_risk": by_risk,
        "risk_score": risk_score,
        "overall_status": overall_status,
        "recommendation": recommendation,
        "vulnerability_types": list(vuln_types.keys()),
        "top_vulnerabilities": alerts.get("alerts", [])[:10],  # Top 10
    }


# ===== Internal Helper Functions =====

def _run_zap_docker_scan(
    target_url: str,
    scan_type: str,
    ajax_spider: bool
) -> Dict[str, Any]:
    """Run ZAP scan using Docker."""
    
    # Determine script based on scan type
    if scan_type == "baseline":
        script = "zap-baseline.py"
    elif scan_type == "full":
        script = "zap-full-scan.py"
    else:
        script = "zap-baseline.py"
    
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}:/zap/wrk:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        script,
        "-t", target_url,
        "-J", f"zap-{scan_type}-report.json",
        "-r", f"zap-{scan_type}-report.html",
    ]
    
    if ajax_spider:
        cmd.append("-j")  # Enable AJAX spider
    
    try:
        # Check if Docker is available
        docker_check = subprocess.run(["docker", "--version"], capture_output=True)
        if docker_check.returncode != 0:
            return {
                "status": "error",
                "error_message": "Docker is not installed or not running",
            }
        
        print(f"Starting ZAP {scan_type} scan on {target_url}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )
        
        # ZAP exit codes: 0=pass, 1=warnings, 2=failures
        if result.returncode in [0, 1, 2]:
            status = "success"
            if result.returncode == 1:
                message = "Scan completed with warnings"
            elif result.returncode == 2:
                message = "Scan completed with failures found"
            else:
                message = "Scan completed successfully"
        else:
            status = "error"
            message = result.stderr or "Unknown error"
        
        return {
            "status": status,
            "scan_type": scan_type,
            "target_url": target_url,
            "exit_code": result.returncode,
            "message": message,
            "report_json": f"zap-{scan_type}-report.json",
            "report_html": f"zap-{scan_type}-report.html",
            "ajax_spider": ajax_spider,
        }
        
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "Docker not found. Install Docker to use ZAP scans.",
            "install_url": "https://docs.docker.com/get-docker/"
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_message": "ZAP scan timed out after 1 hour",
        }
    except Exception as e:
        logger.error(f"ZAP Docker scan error: {e}")
        return {
            "status": "error",
            "error_message": str(e),
        }


def _start_zap_api_scan_internal(
    target_url: str,
    scan_type: str,
    ajax_spider: bool
) -> Dict[str, Any]:
    """Start ZAP scan using the ZAP API (requires running ZAP daemon)."""
    
    try:
        with httpx.Client(timeout=30) as client:
            # Access target URL
            response = client.get(
                f"{ZAP_API_URL}/JSON/core/action/accessUrl/",
                params={"apikey": ZAP_API_KEY, "url": target_url}
            )
            
            if response.status_code != 200:
                return {
                    "status": "error",
                    "error_message": f"Failed to access target URL: {response.status_code}",
                }
            
            # Start spider
            spider_response = client.get(
                f"{ZAP_API_URL}/JSON/spider/action/scan/",
                params={"apikey": ZAP_API_KEY, "url": target_url}
            )
            
            spider_id = spider_response.json().get("scan")
            
            # Optionally start AJAX spider
            ajax_id = None
            if ajax_spider:
                ajax_response = client.get(
                    f"{ZAP_API_URL}/JSON/ajaxSpider/action/scan/",
                    params={"apikey": ZAP_API_KEY, "url": target_url}
                )
                ajax_id = ajax_response.json().get("scan")
            
            return {
                "status": "success",
                "scan_type": scan_type,
                "target_url": target_url,
                "spider_scan_id": spider_id,
                "ajax_spider_id": ajax_id,
                "message": "Scan initiated via ZAP API",
            }
            
    except httpx.ConnectError:
        return {
            "status": "error",
            "error_message": f"Cannot connect to ZAP at {ZAP_API_URL}",
            "suggestion": "Start ZAP or use Docker mode (use_docker=True)",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }
