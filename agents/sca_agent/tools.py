"""
SCA Agent Tools - Dependency vulnerability scanning.

Tools for Software Composition Analysis using multiple backends:
- Snyk (commercial, requires API key)
- pip-audit (open-source, Python)
- npm audit (built-in, JavaScript)
- Safety (open-source, Python)
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


def run_snyk_scan(
    target_path: str = ".",
    package_manager: str = "auto"
) -> Dict[str, Any]:
    """
    Run Snyk vulnerability scan on dependencies.
    
    Snyk provides comprehensive vulnerability database and fix suggestions.
    Requires SNYK_TOKEN environment variable.
    
    First tries CLI, then falls back to API if CLI not installed.
    
    Args:
        target_path: Path to project root
        package_manager: Package manager (auto, pip, npm, maven, gradle)
    
    Returns:
        Dictionary with scan results
    """
    token = os.getenv("SNYK_TOKEN", "")
    
    if not token:
        return {
            "status": "skipped",
            "message": "Snyk token not configured. Set SNYK_TOKEN env var.",
            "fallback": "Use run_pip_audit or run_npm_audit as alternatives",
            "setup_url": "https://app.snyk.io/account"
        }
    
    # First try CLI
    try:
        cmd = ["snyk", "test", "--json"]
        
        if package_manager != "auto":
            cmd.extend(["--package-manager", package_manager])
        
        result = subprocess.run(
            cmd,
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "SNYK_TOKEN": token}
        )
        
        try:
            output = json.loads(result.stdout)
            vulnerabilities = output.get("vulnerabilities", [])
            
            parsed_vulns = []
            for vuln in vulnerabilities:
                parsed_vulns.append({
                    "id": vuln.get("id"),
                    "package": vuln.get("packageName"),
                    "version": vuln.get("version"),
                    "severity": vuln.get("severity", "medium"),
                    "title": vuln.get("title"),
                    "description": vuln.get("description", "")[:500],
                    "cve_ids": vuln.get("identifiers", {}).get("CVE", []),
                    "cvss_score": vuln.get("cvssScore"),
                    "exploitable": vuln.get("isUpgradable") or vuln.get("isPatchable"),
                    "fix_version": vuln.get("fixedIn", [None])[0],
                    "upgrade_path": vuln.get("upgradePath", []),
                })
            
            return {
                "status": "success",
                "tool": "snyk",
                "target_path": target_path,
                "total_vulnerabilities": len(parsed_vulns),
                "vulnerabilities": parsed_vulns,
                "ok": output.get("ok", len(vulnerabilities) == 0),
                "dependencies_count": output.get("dependencyCount", 0),
            }
            
        except json.JSONDecodeError:
            return {
                "status": "error",
                "error_message": "Failed to parse Snyk output",
                "raw_output": result.stdout[:500],
            }
            
    except FileNotFoundError:
        # CLI not installed - try API fallback
        logger.info("Snyk CLI not found, trying API fallback...")
        return _run_snyk_api_scan(target_path, token)
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }


def _run_snyk_api_scan(target_path: str, token: str) -> Dict[str, Any]:
    """
    Scan using Snyk API directly (fallback when CLI not installed).
    
    Uses the test endpoint to check packages from requirements.txt.
    """
    req_file = os.path.join(target_path, "requirements.txt")
    
    if not os.path.exists(req_file):
        return {
            "status": "error",
            "error_message": "Snyk API fallback requires requirements.txt",
            "suggestion": "Install Snyk CLI: npm install -g snyk"
        }
    
    # Parse requirements.txt to get packages
    packages = []
    try:
        with open(req_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    # Parse package==version or package>=version
                    for sep in ['==', '>=', '<=', '~=', '!=', '<', '>']:
                        if sep in line:
                            name, version = line.split(sep, 1)
                            packages.append({"name": name.strip(), "version": version.strip().split(',')[0]})
                            break
                    else:
                        packages.append({"name": line.strip(), "version": "latest"})
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Failed to parse requirements.txt: {e}"
        }
    
    if not packages:
        return {
            "status": "success",
            "tool": "snyk-api",
            "total_vulnerabilities": 0,
            "vulnerabilities": [],
            "message": "No packages found in requirements.txt"
        }
    
    # Call Snyk API to test packages
    try:
        headers = {
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
        }
        
        all_vulns = []
        
        # Snyk API test endpoint for pip packages
        # Note: Free tier may have rate limits
        for pkg in packages[:20]:  # Limit to first 20 packages
            try:
                url = f"https://api.snyk.io/v1/test/pip/{pkg['name']}/{pkg['version']}"
                
                with httpx.Client(timeout=30) as client:
                    response = client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    issues = data.get("issues", {}).get("vulnerabilities", [])
                    
                    for issue in issues:
                        all_vulns.append({
                            "id": issue.get("id"),
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "severity": issue.get("severity", "medium"),
                            "title": issue.get("title"),
                            "description": issue.get("description", "")[:300],
                            "cve_ids": issue.get("identifiers", {}).get("CVE", []),
                            "cvss_score": issue.get("cvssScore"),
                            "fix_version": issue.get("fixedIn", [None])[0] if issue.get("fixedIn") else None,
                        })
                elif response.status_code == 404:
                    # Package not in Snyk database, skip
                    continue
                elif response.status_code == 401:
                    return {
                        "status": "error",
                        "error_message": "Invalid Snyk API token",
                    }
                elif response.status_code == 429:
                    logger.warning("Snyk API rate limit reached")
                    break
                    
            except Exception as e:
                logger.warning(f"Failed to check {pkg['name']}: {e}")
                continue
        
        return {
            "status": "success",
            "tool": "snyk-api",
            "target_path": target_path,
            "total_vulnerabilities": len(all_vulns),
            "vulnerabilities": all_vulns,
            "packages_checked": len(packages[:20]),
            "note": "API fallback - install Snyk CLI for full scanning"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Snyk API error: {e}",
        }



# ===== run_pip_audit COMMENTED OUT =====
# NOTE: Re-enable by removing the triple quotes
'''
def run_pip_audit(target_path: str = ".") -> Dict[str, Any]:
    """
    Run pip-audit to scan Python dependencies for vulnerabilities.
    
    pip-audit is an open-source tool that checks installed packages
    against the Python Packaging Advisory Database.
    
    Args:
        target_path: Path to project (looks for requirements.txt)
    
    Returns:
        Dictionary with scan results
    """
    try:
        import sys
        python_dir = os.path.dirname(sys.executable)
        pip_audit_path = os.path.join(python_dir, "pip-audit")
        
        if not os.path.exists(pip_audit_path):
            pip_audit_path = "pip-audit"
        
        cmd = [pip_audit_path, "--format", "json"]
        
        # Check for requirements.txt
        req_file = os.path.join(target_path, "requirements.txt")
        if os.path.exists(req_file):
            cmd.extend(["-r", req_file])
        
        result = subprocess.run(
            cmd,
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        try:
            output = json.loads(result.stdout) if result.stdout else []
            
            # pip-audit returns a list of vulnerabilities
            if isinstance(output, list):
                vulnerabilities = output
            else:
                vulnerabilities = output.get("dependencies", [])
            
            parsed_vulns = []
            for vuln in vulnerabilities:
                # Handle different pip-audit output formats
                if isinstance(vuln, dict):
                    vulns_list = vuln.get("vulns", [])
                    package_name = vuln.get("name", "unknown")
                    version = vuln.get("version", "unknown")
                    
                    for v in vulns_list:
                        parsed_vulns.append({
                            "id": v.get("id"),
                            "package": package_name,
                            "version": version,
                            "severity": _map_pip_audit_severity(v.get("id", "")),
                            "title": v.get("id"),
                            "description": v.get("description", ""),
                            "fix_version": v.get("fix_versions", [None])[0] if v.get("fix_versions") else None,
                            "aliases": v.get("aliases", []),
                        })
            
            return {
                "status": "success",
                "tool": "pip-audit",
                "target_path": target_path,
                "total_vulnerabilities": len(parsed_vulns),
                "vulnerabilities": parsed_vulns,
            }
            
        except json.JSONDecodeError:
            # pip-audit might output plain text on error
            if "No known vulnerabilities" in result.stdout:
                return {
                    "status": "success",
                    "tool": "pip-audit",
                    "total_vulnerabilities": 0,
                    "vulnerabilities": [],
                    "message": "No known vulnerabilities found"
                }
            return {
                "status": "error",
                "error_message": "Failed to parse pip-audit output",
                "raw_output": result.stdout[:500],
            }
            
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "pip-audit not installed. Install with: pip install pip-audit",
            "install_command": "pip install pip-audit"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }
'''

# Stub function while pip-audit is commented out
def run_pip_audit(target_path: str = ".") -> Dict[str, Any]:
    """Temporarily disabled - use run_snyk_scan instead."""
    return {
        "status": "skipped",
        "message": "run_pip_audit is currently disabled. Use run_snyk_scan instead.",
    }



def run_npm_audit(target_path: str = ".") -> Dict[str, Any]:
    """
    Run npm audit to scan JavaScript dependencies.
    
    Uses npm's built-in audit functionality to check package.json
    dependencies against the npm security advisory database.
    
    Args:
        target_path: Path to project with package.json
    
    Returns:
        Dictionary with scan results
    """
    package_json = os.path.join(target_path, "package.json")
    if not os.path.exists(package_json):
        return {
            "status": "skipped",
            "message": "No package.json found - not a JavaScript project"
        }
    
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        try:
            output = json.loads(result.stdout)
            
            advisories = output.get("advisories", {})
            if not advisories:
                # npm 7+ format
                vulnerabilities_data = output.get("vulnerabilities", {})
                advisories = vulnerabilities_data
            
            parsed_vulns = []
            for key, adv in advisories.items():
                if isinstance(adv, dict):
                    parsed_vulns.append({
                        "id": adv.get("id") or key,
                        "package": adv.get("module_name") or adv.get("name") or key,
                        "severity": adv.get("severity", "moderate"),
                        "title": adv.get("title", adv.get("name", "")),
                        "description": adv.get("overview", "")[:500],
                        "cve_ids": adv.get("cves", []),
                        "fix_available": adv.get("fixAvailable", False),
                        "vulnerable_versions": adv.get("vulnerable_versions", adv.get("range", "")),
                        "patched_versions": adv.get("patched_versions", ""),
                    })
            
            metadata = output.get("metadata", {})
            
            return {
                "status": "success",
                "tool": "npm-audit",
                "target_path": target_path,
                "total_vulnerabilities": len(parsed_vulns),
                "vulnerabilities": parsed_vulns,
                "dependencies_count": metadata.get("dependencies", {}).get("prod", 0),
                "dev_dependencies_count": metadata.get("dependencies", {}).get("dev", 0),
            }
            
        except json.JSONDecodeError:
            return {
                "status": "error",
                "error_message": "Failed to parse npm audit output",
                "stderr": result.stderr[:500],
            }
            
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "npm not installed",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }


def run_safety_check(target_path: str = ".") -> Dict[str, Any]:
    """
    Run Safety check for Python dependencies.
    
    Safety is an open-source tool that checks Python dependencies
    against a database of known security vulnerabilities.
    
    Args:
        target_path: Path to project
    
    Returns:
        Dictionary with scan results
    """
    try:
        cmd = ["safety", "check", "--json"]
        
        req_file = os.path.join(target_path, "requirements.txt")
        if os.path.exists(req_file):
            cmd.extend(["-r", req_file])
        
        result = subprocess.run(
            cmd,
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        try:
            output = json.loads(result.stdout)
            
            # Safety returns vulnerabilities array
            vulnerabilities = output if isinstance(output, list) else []
            
            parsed_vulns = []
            for vuln in vulnerabilities:
                if isinstance(vuln, list) and len(vuln) >= 5:
                    # Safety format: [package, affected, installed, description, id]
                    parsed_vulns.append({
                        "id": vuln[4] if len(vuln) > 4 else "unknown",
                        "package": vuln[0],
                        "version": vuln[2],
                        "description": vuln[3] if len(vuln) > 3 else "",
                        "affected_versions": vuln[1],
                    })
            
            return {
                "status": "success",
                "tool": "safety",
                "target_path": target_path,
                "total_vulnerabilities": len(parsed_vulns),
                "vulnerabilities": parsed_vulns,
            }
            
        except json.JSONDecodeError:
            if result.returncode == 0:
                return {
                    "status": "success",
                    "tool": "safety",
                    "total_vulnerabilities": 0,
                    "vulnerabilities": [],
                }
            return {
                "status": "error",
                "error_message": "Failed to parse Safety output",
            }
            
    except FileNotFoundError:
        return {
            "status": "error",
            "error_message": "Safety not installed. Install with: pip install safety",
            "install_command": "pip install safety"
        }
    except Exception as e:
        return {
            "status": "error",
            "error_message": str(e),
        }


def get_upgrade_recommendations(
    vulnerabilities: List[Dict[str, Any]],
    conservative: bool = True
) -> Dict[str, Any]:
    """
    Generate upgrade recommendations for vulnerable packages.
    
    Args:
        vulnerabilities: List of vulnerabilities from scan
        conservative: If True, suggest minimum safe version
    
    Returns:
        Dictionary with upgrade recommendations
    """
    recommendations = []
    
    for vuln in vulnerabilities:
        package = vuln.get("package", "unknown")
        current_version = vuln.get("version", "unknown")
        fix_version = vuln.get("fix_version") or vuln.get("patched_versions")
        severity = vuln.get("severity", "medium")
        
        if fix_version:
            rec = {
                "package": package,
                "current_version": current_version,
                "recommended_version": fix_version,
                "severity": severity,
                "action": "upgrade",
                "command": f"pip install {package}>={fix_version}" if not package.startswith("@") else f"npm install {package}@{fix_version}",
                "priority": _severity_to_priority(severity),
            }
        else:
            rec = {
                "package": package,
                "current_version": current_version,
                "recommended_version": None,
                "severity": severity,
                "action": "review",
                "note": "No fix available - consider alternative package or accept risk",
                "priority": _severity_to_priority(severity),
            }
        
        recommendations.append(rec)
    
    # Sort by priority
    recommendations.sort(key=lambda x: x["priority"])
    
    return {
        "status": "success",
        "total_recommendations": len(recommendations),
        "upgradeable": len([r for r in recommendations if r["action"] == "upgrade"]),
        "needs_review": len([r for r in recommendations if r["action"] == "review"]),
        "recommendations": recommendations,
    }


def generate_sca_report(
    scan_results: Dict[str, Any],
    recommendations: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate a comprehensive SCA report.
    
    Args:
        scan_results: Output from any scan tool
        recommendations: Optional upgrade recommendations
    
    Returns:
        Dictionary with SCA report
    """
    vulnerabilities = scan_results.get("vulnerabilities", [])
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "medium").lower()
        # Normalize severity names
        if sev in ["moderate"]:
            sev = "medium"
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Calculate risk score
    risk_score = (
        severity_counts["critical"] * 15 +
        severity_counts["high"] * 10 +
        severity_counts["medium"] * 5 +
        severity_counts["low"] * 1
    )
    risk_score = min(100, risk_score)
    
    # Determine overall status
    if severity_counts["critical"] > 0:
        overall_status = "critical"
        recommendation = "BLOCK: Critical vulnerabilities in dependencies. Immediate action required!"
    elif severity_counts["high"] > 0:
        overall_status = "high_risk"
        recommendation = "URGENT: High severity dependency vulnerabilities need attention"
    elif severity_counts["medium"] > 0:
        overall_status = "medium_risk"
        recommendation = "WARN: Medium severity issues. Plan upgrades soon"
    else:
        overall_status = "low_risk"
        recommendation = "PASS: Dependencies look secure"
    
    # Identify unique packages
    vulnerable_packages = list(set(v.get("package", "unknown") for v in vulnerabilities))
    
    report = {
        "status": "success",
        "report_type": "SCA",
        "timestamp": datetime.now().isoformat(),
        "tool": scan_results.get("tool", "unknown"),
        "total_vulnerabilities": len(vulnerabilities),
        "by_severity": severity_counts,
        "risk_score": risk_score,
        "overall_status": overall_status,
        "recommendation": recommendation,
        "vulnerable_packages": vulnerable_packages,
        "vulnerabilities": vulnerabilities[:20],  # Top 20 for report
    }
    
    if recommendations:
        report["upgrade_recommendations"] = recommendations.get("recommendations", [])[:10]
        report["upgradeable_count"] = recommendations.get("upgradeable", 0)
    
    return report


# ===== Helper Functions =====

def _map_pip_audit_severity(vuln_id: str) -> str:
    """Map pip-audit vulnerability ID to severity."""
    # PYSEC IDs don't have built-in severity
    # Would need to query OSV database for actual severity
    return "medium"


def _severity_to_priority(severity: str) -> int:
    """Convert severity to numeric priority (lower = higher priority)."""
    priority_map = {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "moderate": 3,
        "low": 4,
    }
    return priority_map.get(severity.lower(), 3)


def generate_snyk_github_workflow(
    project_type: str = "python",
    severity_threshold: str = "high",
    monitor_on_main: bool = True
) -> Dict[str, Any]:
    """
    Generate GitHub Actions workflow YAML for Snyk integration.
    
    This creates a workflow configuration matching the gha-devsecops
    reference project approach - running Snyk via GitHub Actions.
    
    Args:
        project_type: Project type (python, node, maven, gradle, etc.)
        severity_threshold: Minimum severity to fail build (low, medium, high, critical)
        monitor_on_main: Whether to run snyk monitor on main branch
    
    Returns:
        Dictionary with workflow configuration
    """
    # Map project type to Snyk action
    action_map = {
        "python": "snyk/actions/python@master",
        "node": "snyk/actions/node@master",
        "maven": "snyk/actions/maven@master",
        "gradle": "snyk/actions/gradle@master",
        "docker": "snyk/actions/docker@master",
        # "iac": "snyk/actions/iac@master",
    }
    
    snyk_action = action_map.get(project_type, "snyk/actions/python@master")
    
    # Generate workflow YAML
    workflow = f'''name: Snyk Security Scan

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  snyk-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Snyk to check for vulnerabilities
        uses: {snyk_action}
        env:
          SNYK_TOKEN: ${{{{ secrets.SNYK_TOKEN }}}}
        with:
          command: test
          args: --severity-threshold={severity_threshold}
        continue-on-error: true
'''
    
    if monitor_on_main:
        workflow += f'''
      - name: Run Snyk to monitor project
        if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/master'
        uses: {snyk_action}
        env:
          SNYK_TOKEN: ${{{{ secrets.SNYK_TOKEN }}}}
        with:
          command: monitor
          args: --project-name=${{{{ github.repository }}}}
'''
    
    workflow += '''
      - name: Upload Snyk results to GitHub
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: snyk.sarif
        continue-on-error: true
'''
    
    return {
        "status": "success",
        "project_type": project_type,
        "severity_threshold": severity_threshold,
        "snyk_action": snyk_action,
        "workflow_yaml": workflow,
        "setup_instructions": [
            "1. Add SNYK_TOKEN to your repository secrets (Settings -> Secrets)",
            "2. Save the workflow YAML to .github/workflows/snyk.yml",
            "3. Push to trigger the workflow",
            "4. View results in the Security tab or Snyk dashboard",
        ],
        "get_token_url": "https://app.snyk.io/account",
    }

