"""
Test SAST Agent with deliberately vulnerable code samples.

This script:
1. Creates sample vulnerable code files
2. Runs Semgrep scan via SAST agent tools  
3. Parses and reports findings
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.sast_agent.tools import (
    run_semgrep_scan,
    parse_semgrep_results,
    generate_sast_report,
)


# ===== Vulnerable Code Samples =====

VULNERABLE_PYTHON = '''
"""Sample vulnerable Python code for SAST testing."""

import os
import sqlite3
import subprocess

def sql_injection_vuln(user_input):
    """SQL Injection vulnerability - user input directly in query."""
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # VULNERABLE: Direct string formatting with user input
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def command_injection_vuln(filename):
    """Command injection vulnerability."""
    # VULNERABLE: User input in shell command
    os.system(f"cat {filename}")
    
def hardcoded_secret():
    """Hardcoded credentials."""
    # VULNERABLE: Hardcoded password
    password = "super_secret_password_123"
    api_key = "sk-1234567890abcdef"
    return password, api_key

def path_traversal_vuln(user_path):
    """Path traversal vulnerability."""
    # VULNERABLE: No path validation
    with open(f"/var/data/{user_path}", "r") as f:
        return f.read()

def insecure_deserialization(data):
    """Insecure deserialization."""
    import pickle
    # VULNERABLE: Deserializing untrusted data
    return pickle.loads(data)

def weak_crypto():
    """Weak cryptography."""
    import hashlib
    # VULNERABLE: MD5 is weak for passwords
    password = "secret"
    return hashlib.md5(password.encode()).hexdigest()
'''

VULNERABLE_JS = '''
// Sample vulnerable JavaScript code for SAST testing

// SQL Injection
function getUser(userId) {
    // VULNERABLE: String concatenation in query
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    return db.execute(query);
}

// XSS vulnerability
function displayMessage(userMessage) {
    // VULNERABLE: innerHTML with user content
    document.getElementById("output").innerHTML = userMessage;
}

// Eval vulnerability
function processCode(code) {
    // VULNERABLE: eval with user input
    return eval(code);
}

// Hardcoded secret
const API_KEY = "sk-live-1234567890abcdef";
const DB_PASSWORD = "admin123";
'''


def create_test_files(temp_dir: str) -> dict:
    """Create vulnerable code files for testing."""
    files = {}
    
    # Python file
    py_path = os.path.join(temp_dir, "vulnerable_app.py")
    with open(py_path, "w") as f:
        f.write(VULNERABLE_PYTHON)
    files["python"] = py_path
    
    # JavaScript file
    js_path = os.path.join(temp_dir, "vulnerable_app.js")
    with open(js_path, "w") as f:
        f.write(VULNERABLE_JS)
    files["javascript"] = js_path
    
    return files


def test_sast_agent():
    """Run SAST agent tests."""
    print("\n" + "="*60)
    print("🔍 SAST AGENT TEST SUITE")
    print("="*60)
    
    # Create temp directory with vulnerable files
    temp_dir = tempfile.mkdtemp(prefix="sast_test_")
    print(f"\n📁 Created test directory: {temp_dir}")
    
    try:
        # Create test files
        files = create_test_files(temp_dir)
        print(f"✅ Created {len(files)} vulnerable code files")
        
        # Test 1: Run Semgrep scan
        print("\n" + "-"*40)
        print("🧪 TEST 1: Semgrep Scan")
        print("-"*40)
        
        scan_result = run_semgrep_scan(
            target_path=temp_dir,
            config="auto"
        )
        
        if scan_result["status"] == "success":
            print(f"✅ Scan completed successfully")
            print(f"   Findings: {scan_result['findings_count']}")
        elif scan_result["status"] == "error":
            if "not installed" in scan_result.get("error_message", ""):
                print(f"⚠️  Semgrep not installed: {scan_result.get('install_command')}")
                return False
            else:
                print(f"❌ Scan error: {scan_result.get('error_message')}")
                return False
        else:
            print(f"⚠️  Scan status: {scan_result['status']}")
        
        # Test 2: Parse results
        print("\n" + "-"*40)
        print("🧪 TEST 2: Parse Results")
        print("-"*40)
        
        parsed = parse_semgrep_results(scan_result)
        
        if parsed["status"] == "success":
            print(f"✅ Parsed {parsed['total_count']} vulnerabilities")
            print(f"   By severity: {parsed['by_severity']}")
            
            # Show sample findings
            for vuln in parsed["vulnerabilities"][:5]:
                print(f"\n   🔴 {vuln['type']}")
                print(f"      File: {os.path.basename(vuln['file_path'])}:{vuln['start_line']}")
                print(f"      Severity: {vuln['severity']}")
                if vuln.get('message'):
                    print(f"      Message: {vuln['message'][:80]}...")
        else:
            print(f"⚠️  Parse status: {parsed['status']}")
        
        # Test 3: Generate report
        print("\n" + "-"*40)
        print("🧪 TEST 3: Generate SAST Report")
        print("-"*40)
        
        report = generate_sast_report(parsed)
        
        if report["status"] == "success":
            print(f"✅ Report generated")
            print(f"   Total vulnerabilities: {report['total_vulnerabilities']}")
            print(f"   Risk score: {report['risk_score']}/100")
            print(f"   Status: {report['overall_status']}")
            print(f"   Recommendation: {report['recommendation']}")
        else:
            print(f"⚠️  Report status: {report['status']}")
        
        # Summary
        print("\n" + "="*60)
        print("📋 TEST SUMMARY")
        print("="*60)
        
        total_vulns = parsed.get("total_count", 0)
        if total_vulns > 0:
            print(f"✅ SAST Agent successfully detected {total_vulns} vulnerabilities")
            print(f"   in deliberately vulnerable test code.")
            return True
        else:
            print("⚠️  No vulnerabilities detected (check Semgrep installation)")
            return False
            
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"\n🧹 Cleaned up test directory")


if __name__ == "__main__":
    success = test_sast_agent()
    sys.exit(0 if success else 1)
