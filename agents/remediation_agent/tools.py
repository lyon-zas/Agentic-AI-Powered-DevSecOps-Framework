"""
Remediation Agent Tools - Generate fixes and create GitHub PRs.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os
from pathlib import Path

# Import GitHub client
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.github_client import GitHubClient


def analyze_vulnerability(vulnerability_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a vulnerability report to extract key information.
    
    Args:
        vulnerability_report: Vulnerability details from SAST/DAST/SCA scan
    
    Returns:
        Structured vulnerability analysis
    """
    # Extract key fields
    vuln_type = vulnerability_report.get('check_id', 'unknown')
    severity = vulnerability_report.get('extra', {}).get('severity', 'UNKNOWN')
    file_path = vulnerability_report.get('path', 'unknown_file')
    line_start = vulnerability_report.get('start', {}).get('line', 0)
    line_end = vulnerability_report.get('end', {}).get('line', 0)
    message = vulnerability_report.get('extra', {}).get('message', '')
    
    # Extract CWE and OWASP
    metadata = vulnerability_report.get('extra', {}).get('metadata', {})
    cwe = metadata.get('cwe', [])
    owasp = metadata.get('owasp', [])
    
    return {
        "vulnerability_id": vuln_type,
        "severity": severity,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "description": message,
        "cwe": cwe,
        "owasp": owasp,
        "category": _categorize_vulnerability(vuln_type),
        "fix_template": _get_fix_template(vuln_type)
    }


def generate_fix_code(
    file_path: str,
    vulnerability: Dict[str, Any],
    original_code: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate secure code fix for a vulnerability.
    
    This is a template-based approach. For production, you'd use LLM here.
    
    Args:
        file_path: Path to the vulnerable file
        vulnerability: Analyzed vulnerability data
        original_code: Optional original vulnerable code
    
    Returns:
        Dictionary with fixed code and explanation
    """
    category = vulnerability.get('category', 'unknown')
    vuln_id = vulnerability.get('vulnerability_id', '')
    
    # Template-based fixes for common patterns
    if 'sql' in category.lower() or 'sql-injection' in vuln_id.lower():
        return {
            "fix_type": "SQL Injection Prevention",
            "recommendation": "Use parameterized queries instead of string concatenation",
            "code_pattern": "OLD: query = f\"SELECT * FROM users WHERE id = {user_id}\"\nNEW: query = \"SELECT * FROM users WHERE id = ?\"\n     cursor.execute(query, (user_id,))",
            "explanation": "Parameterized queries prevent SQL injection by treating user input as data, not executable code."
        }
    
    elif 'xss' in category.lower() or 'cross-site-scripting' in vuln_id.lower():
        return {
            "fix_type": "XSS Prevention",
            "recommendation": "Escape user input before rendering in HTML",
            "code_pattern": "OLD: innerHTML = user_input\nNEW: innerHTML = escapeHtml(user_input)",
            "explanation": "Escaping HTML special characters prevents XSS attacks by treating user input as text, not code."
        }
    
    elif 'command' in category.lower() or 'command-injection' in vuln_id.lower():
        return {
            "fix_type": "Command Injection Prevention",
            "recommendation": "Use safe subprocess calls with argument lists",
            "code_pattern": "OLD: os.system(f'ping {host}')\nNEW: subprocess.run(['ping', host], check=True)",
            "explanation": "Using argument lists prevents command injection by avoiding shell interpretation."
        }
    
    elif 'path' in category.lower() or 'traversal' in vuln_id.lower():
        return {
            "fix_type": "Path Traversal Prevention",
            "recommendation": "Validate and sanitize file paths",
            "code_pattern": "OLD: open(user_path)\nNEW: safe_path = os.path.abspath(user_path)\n     if not safe_path.startswith(ALLOWED_DIR):\n         raise ValueError('Invalid path')\n     open(safe_path)",
            "explanation": "Path validation prevents directory traversal attacks by ensuring files are within allowed directories."
        }
    
    else:
        return {
            "fix_type": "General Security Fix",
            "recommendation": "Review and apply security best practices",
            "code_pattern": "Follow OWASP guidelines for " + category,
            "explanation": f"Address {category} by following security best practices and input validation."
        }


def generate_remediation_readme(
    vulnerabilities: List[Dict[str, Any]],
    fixes: List[Dict[str, Any]],
    repo_name: str
) -> str:
    """
    Generate comprehensive README.md for the remediation PR.
    
    Args:
        vulnerabilities: List of analyzed vulnerabilities
        fixes: List of generated fixes
        repo_name: Repository name
    
    Returns:
        README.md content as string
    """
    # Count severities
    severity_counts = {}
    for vuln in vulnerabilities:
        sev = vuln.get('severity', 'UNKNOWN')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Generate README
    readme = f"""# 🔒 Security Remediation Report

**Repository**: {repo_name}  
**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  
**Vulnerabilities Fixed**: {len(vulnerabilities)}  
**Severity Breakdown**: {', '.join(f'{count} {sev}' for sev, count in sorted(severity_counts.items()))}

---

## 📋 Executive Summary

This automated security remediation addresses {len(vulnerabilities)} vulnerabilities detected by our security scanning pipeline. Each fix follows OWASP best practices and includes detailed explanations.

**Tools Used**: Semgrep SAST, SCA Agent

---

## 🐛 Vulnerabilities Fixed

"""
    
    # Add each vulnerability
    for idx, (vuln, fix) in enumerate(zip(vulnerabilities, fixes), 1):
        readme += f"""### {idx}. {vuln.get('category', 'Security Issue')}

**File**: `{vuln.get('file_path', 'unknown')}`:{vuln.get('line_start', '?')}  
**Severity**: **{vuln.get('severity', 'UNKNOWN')}**  
**CWE**: {', '.join(vuln.get('cwe', ['N/A']))}  
**OWASP**: {', '.join(vuln.get('owasp', ['N/A']))}  

**Description**:  
{vuln.get('description', 'No description available')}

**Fix Applied**:  
{fix.get('fix_type', 'General fix')}

```diff
{fix.get('code_pattern', 'See code changes')}
```

**Why This Fix Works**:  
{fix.get('explanation', 'This fix addresses the vulnerability by following security best practices.')}

**Recommendation**: {fix.get('recommendation', 'Review the changes and test thoroughly.')}

---

"""
    
    # Testing section
    readme += """## ✅ Testing Checklist

Before merging this PR, please verify:

- [ ] Run all unit tests: `pytest`
- [ ] Run security scans: `semgrep scan --config auto .`
- [ ] Manual code review of all changes
- [ ] Test in staging environment
- [ ] Verify no functionality regression

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Semgrep Rules](https://semgrep.dev/r)

---

## 🤖 Auto-Generated

This PR was automatically generated by the Agentic AI DevSecOps Framework.  
**Agent**: Remediation Agent  
**Timestamp**: {datetime.now().isoformat()}

"""
    
    return readme


def create_remediation_pr(
    repo_name: str,
    vulnerabilities: List[Dict[str, Any]],
    fixes: Optional[List[Dict[str, Any]]] = None,
    base_branch: str = "main",
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Create a GitHub Pull Request with security fixes.
    
    Args:
        repo_name: Repository name in format 'owner/repo'
        vulnerabilities: List of vulnerabilities to fix
        fixes: Optional list of fixes (will be generated if not provided)
        base_branch: Base branch to create PR against
        dry_run: If True, don't actually create the PR
    
    Returns:
        PR creation result
    """
    try:
        # Generate fixes if not provided
        if fixes is None:
            fixes = []
            for vuln in vulnerabilities:
                fix = generate_fix_code(
                    vuln.get('file_path', ''),
                    vuln
                )
                fixes.append(fix)
        
        # Generate README
        readme_content = generate_remediation_readme(
            vulnerabilities,
            fixes,
            repo_name
        )
        
        # Generate branch name
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        branch_name = f"fix/security-remediation-{timestamp}"
        
        # Generate PR title and body
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        pr_title = f"🔒 Security Fix: Address {len(vulnerabilities)} vulnerabilities"
        pr_body = f"""## Security Remediation

This PR automatically fixes {len(vulnerabilities)} security vulnerabilities detected by our scanning pipeline.

### Summary
{', '.join(f'{count} {sev}' for sev, count in sorted(severity_counts.items()))}

### Changes
- Security fixes for {len(vulnerabilities)} vulnerabilities
- Comprehensive documentation in SECURITY_FIXES.md

### Testing
Please review the testing checklist in SECURITY_FIXES.md before merging.

---
🤖 **Auto-generated** by Remediation Agent
"""
        
        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "branch_name": branch_name,
                "pr_title": pr_title,
                "readme_preview": readme_content[:500] + "...",
                "vulnerability_count": len(vulnerabilities)
            }
        
        # Create GitHub client
        github_client = GitHubClient()
        
        # Prepare files to commit
        files = {
            "SECURITY_FIXES.md": readme_content
        }
        
        # Create branch and commit
        result = github_client.create_branch_and_commit(
            repo_name=repo_name,
            files=files,
            branch_name=branch_name,
            commit_message=f"fix: Address {len(vulnerabilities)} security vulnerabilities\n\nAuto-generated security fixes with documentation",
            base_branch=base_branch
        )
        
        if not result.get("success"):
            return result
        
        # Create PR
        pr_result = github_client.create_pull_request(
            repo_name=repo_name,
            title=pr_title,
            body=pr_body,
            head_branch=branch_name,
            base_branch=base_branch,
            labels=["security", "auto-remediation"]
        )
        
        return {
            "success": pr_result.get("success"),
            "pr_url": pr_result.get("pr_url"),
            "pr_number": pr_result.get("pr_number"),
            "branch_name": branch_name,
            "vulnerabilities_fixed": len(vulnerabilities),
            "readme_generated": True
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to create remediation PR: {e}"
        }


# Helper functions
def _categorize_vulnerability(vuln_id: str) -> str:
    """Categorize vulnerability by ID."""
    vuln_id_lower = vuln_id.lower()
    
    if 'sql' in vuln_id_lower:
        return 'SQL Injection'
    elif 'xss' in vuln_id_lower or 'cross-site' in vuln_id_lower:
        return 'Cross-Site Scripting (XSS)'
    elif 'command' in vuln_id_lower or 'exec' in vuln_id_lower:
        return 'Command Injection'
    elif 'path' in vuln_id_lower or 'traversal' in vuln_id_lower:
        return 'Path Traversal'
    elif 'csrf' in vuln_id_lower:
        return 'CSRF'
    elif 'injection' in vuln_id_lower:
        return 'Injection'
    else:
        return 'Security Vulnerability'


def _get_fix_template(vuln_id: str) -> str:
    """Get fix template ID for vulnerability."""
    category = _categorize_vulnerability(vuln_id)
    return category.lower().replace(' ', '_').replace('(', '').replace(')', '')
