"""
Test SAST Agent with SonarCloud Integration.

Tests:
1. Semgrep local scanning (already verified)
2. SonarCloud API connection
3. Fetching SonarCloud issues
4. Combined SAST report generation
"""

import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.sast_agent.tools import (
    run_semgrep_scan,
    parse_semgrep_results,
    run_sonarcloud_scan,
    get_sonarcloud_issues,
    generate_sast_report,
)


def test_sast_agent():
    """Run SAST agent tests."""
    print("\n" + "="*60)
    print("🔍 SAST AGENT TEST SUITE")
    print("="*60)
    
    # Check for tokens
    sonar_token = os.getenv("SONAR_TOKEN", "")
    if sonar_token:
        print(f"\n✅ SONAR_TOKEN detected ({len(sonar_token)} chars)")
    else:
        print("\n⚠️  SONAR_TOKEN not set - SonarCloud tests will be skipped")
        print("   Set it with: export SONAR_TOKEN='your-token'")
    
    project_path = str(Path(__file__).parent)
    
    # Test 1: Semgrep Scan
    print("\n" + "-"*40)
    print("🧪 TEST 1: Semgrep Scan")
    print("-"*40)
    
    semgrep_result = run_semgrep_scan(project_path, config="auto")
    
    if semgrep_result.get("status") == "success":
        parsed = parse_semgrep_results(semgrep_result.get("raw_output", {}))
        print(f"✅ Semgrep scan completed")
        print(f"   Total findings: {parsed.get('total_count', 0)}")
        print(f"   By severity: {parsed.get('by_severity', {})}")
        
        # Show top vulnerabilities
        for v in parsed.get("vulnerabilities", [])[:3]:
            print(f"\n   🔴 {v.get('type')}")
            print(f"      File: {v.get('file_path', 'N/A')[:40]}:{v.get('start_line', 'N/A')}")
            print(f"      Severity: {v.get('severity')}")
    else:
        print(f"⚠️  Semgrep: {semgrep_result.get('status')} - {semgrep_result.get('message', semgrep_result.get('error_message', 'Unknown'))}")
        parsed = {"status": "error", "vulnerabilities": []}
    
    # Test 2: SonarCloud Connection
    print("\n" + "-"*40)
    print("🧪 TEST 2: SonarCloud API Connection")
    print("-"*40)
    
    # Try to find project key from sonar-project.properties or use a test project
    sonar_project_key = os.getenv("SONAR_PROJECT_KEY", "")
    sonar_org = os.getenv("SONAR_ORG", "")
    
    # Check if sonar-project.properties exists
    sonar_props = os.path.join(project_path, "sonar-project.properties")
    if os.path.exists(sonar_props):
        with open(sonar_props, 'r') as f:
            for line in f:
                if line.startswith("sonar.projectKey="):
                    sonar_project_key = line.split("=", 1)[1].strip()
                elif line.startswith("sonar.organization="):
                    sonar_org = line.split("=", 1)[1].strip()
    
    if sonar_token and sonar_project_key:
        sonar_result = run_sonarcloud_scan(
            project_key=sonar_project_key,
            organization=sonar_org,
            token=sonar_token
        )
        
        if sonar_result.get("status") == "success":
            print(f"✅ SonarCloud connection successful")
            print(f"   Project: {sonar_result.get('project_key')}")
            print(f"   Last analysis: {sonar_result.get('last_analysis_date', 'N/A')}")
        elif sonar_result.get("status") == "no_analysis":
            print(f"⚠️  Project found but no analysis yet")
            print(f"   Push code to trigger analysis")
        else:
            print(f"❌ SonarCloud error: {sonar_result.get('error_message')}")
    else:
        if not sonar_token:
            print("⏭️  Skipped (no SONAR_TOKEN)")
        else:
            print("⏭️  Skipped (no project key - create sonar-project.properties)")
        sonar_result = {"status": "skipped"}
    
    # Test 3: Get SonarCloud Issues
    print("\n" + "-"*40)
    print("🧪 TEST 3: SonarCloud Security Issues")
    print("-"*40)
    
    if sonar_token and sonar_project_key:
        issues_result = get_sonarcloud_issues(
            project_key=sonar_project_key,
            severities="CRITICAL,MAJOR,BLOCKER",
            token=sonar_token
        )
        
        if issues_result.get("status") == "success":
            print(f"✅ Retrieved SonarCloud issues")
            print(f"   Total issues: {issues_result.get('total_issues', 0)}")
            
            for v in issues_result.get("vulnerabilities", [])[:3]:
                print(f"\n   🔴 {v.get('type')}: {v.get('message', 'N/A')[:50]}")
                print(f"      File: {v.get('file_path', 'N/A')}")
                print(f"      Severity: {v.get('severity')}")
        else:
            print(f"⚠️  Could not fetch issues: {issues_result.get('status')}")
        sonar_issues = issues_result
    else:
        print("⏭️  Skipped (SonarCloud not configured)")
        sonar_issues = {"status": "skipped", "vulnerabilities": []}
    
    # Test 4: Generate SAST Report
    print("\n" + "-"*40)
    print("🧪 TEST 4: Generate Combined SAST Report")
    print("-"*40)
    
    report = generate_sast_report(
        semgrep_results=parsed,
        sonarcloud_results=sonar_issues if sonar_issues.get("status") == "success" else None
    )
    
    print(f"✅ SAST Report generated")
    print(f"   Total vulnerabilities: {report.get('total_vulnerabilities', 0)}")
    print(f"   Risk score: {report.get('risk_score', 0)}/100")
    print(f"   Status: {report.get('overall_status')}")
    print(f"   Sources: {report.get('sources', [])}")
    print(f"   Recommendation: {report.get('recommendation', 'N/A')}")
    
    # Summary
    print("\n" + "="*60)
    print("📋 TEST SUMMARY")
    print("="*60)
    
    semgrep_ok = parsed.get("status") == "success"
    sonar_ok = sonar_result.get("status") in ["success", "no_analysis"]
    
    print(f"   Semgrep: {'✅ Passed' if semgrep_ok else '⚠️ Check config'}")
    print(f"   SonarCloud: {'✅ Connected' if sonar_ok else '⚠️ Skipped/Failed'}")
    
    if semgrep_ok:
        print("\n🎉 SAST Agent is working!")
        return True
    else:
        print("\n⚠️  Some tests need attention")
        return False


if __name__ == "__main__":
    success = test_sast_agent()
    sys.exit(0 if success else 1)
