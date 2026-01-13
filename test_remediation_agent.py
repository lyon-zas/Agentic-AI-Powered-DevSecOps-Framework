"""
Test script for remediation agent - Creates a real GitHub PR with security fixes.
"""
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.remediation_agent.tools import (
    analyze_vulnerability,
    generate_fix_code,
    generate_remediation_readme,
    create_remediation_pr
)


def load_semgrep_results(file_path: str = "evaluation/results/semgrep-results.json"):
    """Load Semgrep scan results."""
    if not os.path.exists(file_path):
        print(f"❌ Semgrep results not found at: {file_path}")
        print("Run a Semgrep scan first:")
        print("  semgrep scan --config auto --json > evaluation/results/semgrep-results.json")
        return []
    
    with open(file_path) as f:
        data = json.load(f)
    
    results = data.get('results', [])
    print(f"✅ Loaded {len(results)} vulnerabilities from {file_path}")
    return results


def test_remediation_dry_run():
    """Test remediation agent in dry-run mode (no actual PR creation)."""
    print("\n" + "=" * 70)
    print("🧪 TESTING REMEDIATION AGENT (DRY RUN)")
    print("=" * 70)
    
    # Load vulnerabilities
    vulnerabilities_raw = load_semgrep_results()
    if not vulnerabilities_raw:
        print("\n⚠️  No vulnerabilities to process. Run a security scan first.")
        return
    
    # Take top 5 for testing
    sample_vulns = vulnerabilities_raw[:5]
    print(f"\n📊 Processing {len(sample_vulns)} vulnerabilities...")
    
    # Analyze vulnerabilities
    analyzed_vulns = []
    for vuln in sample_vulns:
        analyzed = analyze_vulnerability(vuln)
        analyzed_vulns.append(analyzed)
        print(f"  • {analyzed['category']} ({analyzed['severity']}) - {analyzed['file_path']}:{analyzed['line_start']}")
    
    # Generate fixes
    print(f"\n🔧 Generating fixes...")
    fixes = []
    for vuln in analyzed_vulns:
        fix = generate_fix_code(vuln['file_path'], vuln)
        fixes.append(fix)
        print(f"  • {fix['fix_type']}")
    
    # Generate README
    print(f"\n📝 Generating SECURITY_FIXES.md...")
    readme = generate_remediation_readme(analyzed_vulns, fixes, "your-org/your-repo")
    print(f"  ✅ README generated ({len(readme)} chars)")
    print("\n--- README PREVIEW ---")
    print(readme[:500] + "\n... (truncated)")
    
    # Dry run PR creation
    print(f"\n🚀 Creating PR (DRY RUN)...")
    result = create_remediation_pr(
        repo_name="your-org/your-repo",
        vulnerabilities=analyzed_vulns,
        fixes=fixes,
        dry_run=True
    )
    
    if result.get('success'):
        print(f"  ✅ Dry run successful!")
        print(f"     Branch: {result['branch_name']}")
        print(f"     Title: {result['pr_title']}")
        print(f"     Vulns: {result['vulnerability_count']}")
    else:
        print(f"  ❌ Dry run failed: {result.get('error')}")
    
    print("\n" + "=" * 70)
    print("✅ DRY RUN COMPLETE")
    print("" * 70)
    print("\nTo create a real PR:")
    print("1. Set GITHUB_TOKEN environment variable")
    print("2. Run: python test_remediation_agent.py --real-pr your-org/your-repo")
    print("=" * 70)


def test_remediation_real_pr(repo_name: str):
    """Test remediation agent with real PR creation."""
    print("\n" + "=" * 70)
    print("🔥 CREATING REAL GITHUB PR")
    print("=" * 70)
    
    # Check GitHub token
    if not os.getenv('GITHUB_TOKEN'):
        print("❌ GITHUB_TOKEN environment variable not set!")
        print("Set it with: export GITHUB_TOKEN=your_github_token")
        return
    
    print(f"Repository: {repo_name}")
    confirm = input("\n⚠️  This will create a REAL PR. Continue? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted.")
        return
    
    # Load vulnerabilities
    vulnerabilities_raw = load_semgrep_results()
    if not vulnerabilities_raw:
        return
    
    # Take top 5 ERROR severity vulnerabilities
    high_severity = [v for v in vulnerabilities_raw 
                     if v.get('extra', {}).get('severity') == 'ERROR'][:5]
    
    if not high_severity:
        print("❌ No ERROR severity vulnerabilities found")
        return
    
    print(f"\n📊 Processing {len(high_severity)} ERROR severity vulnerabilities...")
    
    # Analyze
    analyzed_vulns = []
    for vuln in high_severity:
        analyzed = analyze_vulnerability(vuln)
        analyzed_vulns.append(analyzed)
        print(f"  • {analyzed['category']} - {analyzed['file_path']}:{analyzed['line_start']}")
    
    # Create PR
    print(f"\n🚀 Creating GitHub PR...")
    result = create_remediation_pr(
        repo_name=repo_name,
        vulnerabilities=analyzed_vulns,
        base_branch="main",
        dry_run=False
    )
    
    if result.get('success'):
        print(f"\n✅ PR CREATED SUCCESSFULLY!")
        print(f"   URL: {result['pr_url']}")
        print(f"   PR Number: #{result['pr_number']}")
        print(f"   Branch: {result['branch_name']}")
        print(f"   Vulnerabilities Fixed: {result['vulnerabilities_fixed']}")
    else:
        print(f"\n❌ PR creation failed:")
        print(f"   Error: {result.get('error')}")
        print(f"   Message: {result.get('message')}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--real-pr":
        if len(sys.argv) < 3:
            print("Usage: python test_remediation_agent.py --real-pr owner/repo")
            sys.exit(1)
        test_remediation_real_pr(sys.argv[2])
    else:
        test_remediation_dry_run()
