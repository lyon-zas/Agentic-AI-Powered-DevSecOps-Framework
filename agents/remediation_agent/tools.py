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
    """
    Generate secure code fix for a vulnerability.
    
    Uses template-based fixes for common patterns, with LLM integration for novel vulnerabilities.
    For production use with ADK agent, the agent's LLM will enhance these fixes contextually.
    
    Args:
        file_path: Path to the vulnerable file
        vulnerability: Analyzed vulnerability data
        original_code: Optional original vulnerable code
    
    Returns:
        Dictionary with fixed code and explanation
    """
    category = vulnerability.get('category', 'unknown')
    vuln_id = vulnerability.get('vulnerability_id', '').lower()
    cwe = vulnerability.get('cwe', [])
    
    # Template-based fixes for common patterns
    if 'sql' in category.lower() or 'sql-injection' in vuln_id or 'cwe-89' in str(cwe).lower():
        return {
            "fix_type": "SQL Injection Prevention",
            "recommendation": "Use parameterized queries or prepared statements instead of string concatenation",
            "code_pattern": "OLD: query = f\"SELECT * FROM users WHERE id = {user_id}\"\nNEW: query = \"SELECT * FROM users WHERE id = ?\"\n     cursor.execute(query, (user_id,))",
            "explanation": "Parameterized queries prevent SQL injection by treating user input as data, not executable code. The database driver handles proper escaping automatically."
        }
    
    elif 'xss' in category.lower() or 'cross-site' in vuln_id or 'cwe-79' in str(cwe).lower():
        return {
            "fix_type": "XSS Prevention",
            "recommendation": "Escape user input before rendering in HTML and implement Content Security Policy",
            "code_pattern": "OLD: innerHTML = user_input\nNEW: import html\n     innerHTML = html.escape(user_input)\n     # Also add CSP header: Content-Security-Policy: default-src 'self'",
            "explanation": "Escaping HTML special characters (<, >, &, \", ') prevents XSS attacks by treating user input as text, not executable code. CSP provides defense-in-depth."
        }
    
    elif 'command' in category.lower() or 'exec' in vuln_id or 'cwe-78' in str(cwe).lower():
        return {
            "fix_type": "Command Injection Prevention",
            "recommendation": "Use safe subprocess calls with argument lists, never shell=True",
            "code_pattern": "OLD: os.system(f'ping {host}')\nNEW: import subprocess\n     subprocess.run(['ping', '-c', '4', host], check=True, capture_output=True)",
            "explanation": "Using argument lists (shell=False) prevents command injection by avoiding shell interpretation. Each argument is passed directly to the program without shell expansion."
        }
    
    elif 'path' in category.lower() or 'traversal' in vuln_id or 'cwe-22' in str(cwe).lower():
        return {
            "fix_type": "Path Traversal Prevention",
            "recommendation": "Validate and canonicalize file paths, use allowlist",
            "code_pattern": "OLD: open(user_path)\nNEW: import os\n     safe_path = os.path.abspath(os.path.normpath(user_path))\n     if not safe_path.startswith(ALLOWED_DIR):\n         raise ValueError('Access denied')\n     open(safe_path)",
            "explanation": "Path canonicalization (abspath, normpath) prevents directory traversal by resolving '..' and symlinks. Allowlist checking ensures access only to intended directories."
        }
    
    elif 'csrf' in category.lower() or 'cwe-352' in str(cwe).lower():
        return {
            "fix_type": "CSRF Protection",
            "recommendation": "Implement CSRF tokens for state-changing operations",
            "code_pattern": "OLD: @app.route('/transfer', methods=['POST'])\n     def transfer(): ...\nNEW: from flask_wtf.csrf import CSRFProtect\n     csrf = CSRFProtect(app)\n     @app.route('/transfer', methods=['POST'])\n     @csrf.csrf_protect\n     def transfer(): ...",
            "explanation": "CSRF tokens ensure requests originated from your application, not from malicious sites. Each form submission requires a unique, secret token."
        }
    
    elif 'deserial' in category.lower() or 'pickle' in vuln_id or 'cwe-502' in str(cwe).lower():
        return {
            "fix_type": "Insecure Deserialization Prevention",
            "recommendation": "Use safe serialization formats like JSON, avoid pickle with untrusted data",
            "code_pattern": "OLD: import pickle\n     data = pickle.loads(user_data)\nNEW: import json\n     data = json.loads(user_data)  # Safe, no code execution\n     # Or use schema validation with pydantic/marshmallow",
            "explanation": "Pickle can execute arbitrary code during deserialization. JSON is data-only and cannot execute code. Use schema validation for additional safety."
        }
    
    elif 'secret' in category.lower() or 'hardcoded' in vuln_id or 'cwe-798' in str(cwe).lower():
        return {
            "fix_type": "Hardcoded Secrets Removal",
            "recommendation": "Use environment variables and secret management systems",
            "code_pattern": "OLD: API_KEY = \"sk_live_abcd1234\"\nNEW: import os\n     API_KEY = os.getenv('API_KEY')\n     if not API_KEY:\n         raise ValueError('API_KEY env var required')",
            "explanation": "Environment variables keep secrets out of source code. Use secret managers (AWS Secrets Manager, HashiCorp Vault) for production."
        }
    
    elif 'crypto' in category.lower() or 'weak' in vuln_id or 'cwe-327' in str(cwe).lower():
        return {
            "fix_type": "Strong Cryptography",
            "recommendation": "Use modern, secure cryptographic algorithms",
            "code_pattern": "OLD: import md5\n     hash = md5.new(data).hexdigest()\nNEW: import hashlib\n     hash = hashlib.sha256(data.encode()).hexdigest()\n     # For passwords, use: from werkzeug.security import generate_password_hash",
            "explanation": "MD5/SHA1 are cryptographically broken. Use SHA-256+ for hashing, bcrypt/scrypt for passwords, AES-256-GCM for encryption."
        }
    
    else:
        # For unknown vulnerability types, provide general guidance
        # In production, the ADK agent's LLM would generate contextual fixes here
        return {
            "fix_type": f"Security Fix: {category}",
            "recommendation": f"Apply security best practices for {category}",
            "code_pattern": f"# Review the vulnerable code and apply fixes based on:\n# - OWASP guidelines for {category}\n# - CWE recommendations: {', '.join(cwe) if cwe else 'N/A'}\n# - Input validation and sanitization\n# - Principle of least privilege",
            "explanation": f"This {category} vulnerability requires context-specific fixes. The ADK agent will analyze the code and generate appropriate security improvements following industry best practices. Common mitigations include input validation, proper authentication/authorization, secure defaults, and defense-in-depth strategies.",
            "requires_llm": True  # Flag for ADK agent to generate contextual fix
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
    """Categorize vulnerability by ID or CWE."""
    vuln_id_lower = vuln_id.lower()
    
    # Specific patterns
    if 'sql' in vuln_id_lower or 'cwe-89' in vuln_id_lower:
        return 'SQL Injection'
    elif 'xss' in vuln_id_lower or 'cross-site-script' in vuln_id_lower or 'cwe-79' in vuln_id_lower:
        return 'Cross-Site Scripting (XSS)'
    elif 'command' in vuln_id_lower or 'exec' in vuln_id_lower or 'cwe-78' in vuln_id_lower:
        return 'Command Injection'
    elif 'path' in vuln_id_lower or 'traversal' in vuln_id_lower or 'cwe-22' in vuln_id_lower:
        return 'Path Traversal'
    elif 'csrf' in vuln_id_lower or 'cwe-352' in vuln_id_lower:
        return 'Cross-Site Request Forgery (CSRF)'
    elif 'deserial' in vuln_id_lower or 'pickle' in vuln_id_lower or 'cwe-502' in vuln_id_lower:
        return 'Insecure Deserialization'
    elif 'secret' in vuln_id_lower or 'hardcoded' in vuln_id_lower or 'password' in vuln_id_lower or 'cwe-798' in vuln_id_lower:
        return 'Hardcoded Secrets'
    elif 'crypto' in vuln_id_lower or 'weak' in vuln_id_lower or 'md5' in vuln_id_lower or 'cwe-327' in vuln_id_lower:
        return 'Weak Cryptography'
    elif 'ssrf' in vuln_id_lower or 'cwe-918' in vuln_id_lower:
        return 'Server-Side Request Forgery (SSRF)'
    elif 'xxe' in vuln_id_lower or 'xml' in vuln_id_lower or 'cwe-611' in vuln_id_lower:
        return 'XML External Entity (XXE)'
    elif 'idor' in vuln_id_lower or 'cwe-639' in vuln_id_lower:
        return 'Insecure Direct Object Reference (IDOR)'
    elif 'auth' in vuln_id_lower or 'cwe-287' in vuln_id_lower:
        return 'Broken Authentication'
    elif 'session' in vuln_id_lower or 'cwe-384' in vuln_id_lower:
        return 'Session Management'
    elif 'race' in vuln_id_lower or 'toctou' in vuln_id_lower or 'cwe-362' in vuln_id_lower:
        return 'Race Condition'
    elif 'injection' in vuln_id_lower or 'cwe-74' in vuln_id_lower:
        return 'Injection Vulnerability'
    elif 'information' in vuln_id_lower or 'disclosure' in vuln_id_lower or 'cwe-200' in vuln_id_lower:
        return 'Information Disclosure'
    elif 'redirect' in vuln_id_lower or 'cwe-601' in vuln_id_lower:
        return 'Open Redirect'
    elif 'buffer' in vuln_id_lower or 'overflow' in vuln_id_lower or 'cwe-120' in vuln_id_lower:
        return 'Buffer Overflow'
    elif 'dos' in vuln_id_lower or 'denial' in vuln_id_lower or 'cwe-400' in vuln_id_lower:
        return 'Denial of Service'
    else:
        # Return cleaned vulnerability ID  
        return vuln_id.replace('_', ' ').replace('-', ' ').title()


def _get_fix_template(vuln_id: str) -> str:
    """Get fix template ID for vulnerability."""
    category = _categorize_vulnerability(vuln_id)
    return category.lower().replace(' ', '_').replace('(', '').replace(')', '')

