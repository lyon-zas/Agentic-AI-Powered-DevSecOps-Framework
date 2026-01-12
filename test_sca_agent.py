"""
Test SCA Agent with Snyk Integration.

This script tests the SCA agent tools including:
1. Snyk scan (requires SNYK_TOKEN env var)
2. pip-audit for Python dependencies
3. Upgrade recommendations
4. SCA report generation
"""

import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.sca_agent.tools import (
    run_snyk_scan,
    run_pip_audit,
    run_safety_check,
    get_upgrade_recommendations,
    generate_sca_report,
)


def test_sca_agent():
    """Run SCA agent tests."""
    print("\n" + "="*60)
    print("🔍 SCA AGENT TEST SUITE")
    print("="*60)
    
    # Check for Snyk token
    snyk_token = os.getenv("SNYK_TOKEN", "")
    if snyk_token:
        print(f"\n✅ SNYK_TOKEN detected ({len(snyk_token)} chars)")
    else:
        print("\n⚠️  SNYK_TOKEN not set - Snyk tests will be skipped")
        print("   Set it with: export SNYK_TOKEN='your-token'")
    
    project_path = str(Path(__file__).parent)
    
    # Test 1: Snyk Scan
    print("\n" + "-"*40)
    print("🧪 TEST 1: Snyk Scan")
    print("-"*40)
    
    if snyk_token:
        snyk_result = run_snyk_scan(project_path)
        
        if snyk_result["status"] == "success":
            print(f"✅ Snyk scan completed")
            print(f"   Total vulnerabilities: {snyk_result.get('total_vulnerabilities', 0)}")
            print(f"   Dependencies scanned: {snyk_result.get('dependencies_count', 'N/A')}")
            
            # Show top vulnerabilities
            vulns = snyk_result.get("vulnerabilities", [])[:3]
            for v in vulns:
                print(f"\n   🔴 {v.get('package')}@{v.get('version')}")
                print(f"      Severity: {v.get('severity')}")
                print(f"      Title: {v.get('title', 'N/A')[:50]}")
                if v.get("fix_version"):
                    print(f"      Fix: Upgrade to {v['fix_version']}")
        elif snyk_result["status"] == "skipped":
            print(f"⚠️  {snyk_result.get('message')}")
        else:
            print(f"❌ Snyk scan error: {snyk_result.get('error_message')}")
            if "not installed" in snyk_result.get("error_message", ""):
                print(f"   Install with: {snyk_result.get('install_command')}")
    else:
        print("⏭️  Skipped (no SNYK_TOKEN)")
    
    # Test 2: pip-audit (no API key needed)
    print("\n" + "-"*40)
    print("🧪 TEST 2: pip-audit (Python dependencies)")
    print("-"*40)
    
    pip_result = run_pip_audit(project_path)
    
    if pip_result["status"] == "success":
        print(f"✅ pip-audit completed")
        print(f"   Vulnerabilities found: {pip_result.get('total_vulnerabilities', 0)}")
        
        for v in pip_result.get("vulnerabilities", [])[:3]:
            print(f"\n   🔴 {v.get('package')}@{v.get('version')}")
            print(f"      ID: {v.get('id')}")
            if v.get("fix_version"):
                print(f"      Fix: Upgrade to {v['fix_version']}")
    elif pip_result["status"] == "error":
        if "not installed" in pip_result.get("error_message", ""):
            print(f"⚠️  pip-audit not installed")
            print(f"   Install with: pip install pip-audit")
        else:
            print(f"❌ pip-audit error: {pip_result.get('error_message')}")
    else:
        print(f"   Status: {pip_result.get('status')}")
        print(f"   Message: {pip_result.get('message', 'N/A')}")
    
    # Test 3: Safety Check
    print("\n" + "-"*40)
    print("🧪 TEST 3: Safety Check")
    print("-"*40)
    
    safety_result = run_safety_check(project_path)
    
    if safety_result["status"] == "success":
        print(f"✅ Safety check completed")
        print(f"   Vulnerabilities found: {safety_result.get('total_vulnerabilities', 0)}")
    elif safety_result["status"] == "error":
        if "not installed" in safety_result.get("error_message", ""):
            print(f"⚠️  Safety not installed")
        else:
            print(f"❌ Safety error: {safety_result.get('error_message')}")
    else:
        print(f"   Status: {safety_result['status']}")
    
    # Test 4: Get upgrade recommendations
    print("\n" + "-"*40)
    print("🧪 TEST 4: Upgrade Recommendations")
    print("-"*40)
    
    # Use whichever scan succeeded
    vulns = []
    if snyk_token and snyk_result.get("status") == "success":
        vulns = snyk_result.get("vulnerabilities", [])
    elif pip_result.get("status") == "success":
        vulns = pip_result.get("vulnerabilities", [])
    
    if vulns:
        recommendations = get_upgrade_recommendations(vulns)
        print(f"✅ Generated {recommendations.get('total_recommendations', 0)} recommendations")
        print(f"   Upgradeable: {recommendations.get('upgradeable', 0)}")
        print(f"   Needs review: {recommendations.get('needs_review', 0)}")
        
        for rec in recommendations.get("recommendations", [])[:3]:
            print(f"\n   📦 {rec.get('package')}")
            print(f"      Current: {rec.get('current_version')}")
            print(f"      Recommended: {rec.get('recommended_version') or 'Manual review'}")
            print(f"      Action: {rec.get('action')}")
    else:
        print("⏭️  No vulnerabilities to generate recommendations for")
    
    # Test 5: Generate SCA Report
    print("\n" + "-"*40)
    print("🧪 TEST 5: Generate SCA Report")
    print("-"*40)
    
    # Use best available scan result
    best_scan = None
    if snyk_token and snyk_result.get("status") == "success":
        best_scan = snyk_result
    elif pip_result.get("status") == "success":
        best_scan = pip_result
    
    if best_scan:
        report = generate_sca_report(best_scan)
        print(f"✅ SCA Report generated")
        print(f"   Total vulnerabilities: {report.get('total_vulnerabilities', 0)}")
        print(f"   Risk score: {report.get('risk_score', 0)}/100")
        print(f"   Status: {report.get('overall_status')}")
        print(f"   Recommendation: {report.get('recommendation')}")
    else:
        print("⏭️  No successful scan to generate report from")
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    
    snyk_ok = snyk_token and snyk_result.get("status") == "success"
    pip_ok = pip_result.get("status") == "success"
    
    print(f"   Snyk: {'✅ Passed' if snyk_ok else '⚠️ Skipped/Failed'}")
    print(f"   pip-audit: {'✅ Passed' if pip_ok else '⚠️ Skipped/Failed'}")
    
    if snyk_ok or pip_ok:
        print("\n🎉 SCA Agent is working with at least one tool!")
        return True
    else:
        print("\n⚠️  No SCA tools working. Install pip-audit or configure Snyk.")
        return False


if __name__ == "__main__":
    success = test_sca_agent()
    sys.exit(0 if success else 1)
