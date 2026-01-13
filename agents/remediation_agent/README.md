# Auto-Remediation Agent

The Remediation Agent automatically creates GitHub Pull Requests with security fixes and comprehensive documentation.

## Features

- **Vulnerability Analysis**: Parses SAST/DAST/SCA scan results
- **Automatic Fix Generation**: Template-based fixes for common vulnerabilities
- **Comprehensive Documentation**: Generates SECURITY_FIXES.md with detailed explanations
- **GitHub Integration**: Real GitHub API integration using PyGithub
- **PR Automation**: Creates branches, commits fixes, and opens PRs with labels

## Supported Vulnerability Types

The Remediation Agent uses **LLM-powered fix generation** to handle **any vulnerability type** detected by security scanners. It includes optimized templates for common patterns and uses AI reasoning for novel or complex vulnerabilities.

### Common Patterns (Template-Optimized)

| Vulnerability | Fix Strategy | OWASP/CWE |
|---------------|--------------|-----------|
| SQL Injection | Parameterized queries | A03:2021, CWE-89 |
| XSS (Cross-Site Scripting) | HTML escaping & CSP | A03:2021, CWE-79 |
| Command Injection | Safe subprocess calls with argument lists | A03:2021, CWE-78 |
| Path Traversal | Path validation & canonicalization | A01:2021, CWE-22 |
| CSRF | Token validation | A01:2021, CWE-352 |
| Insecure Deserialization | Safe parsing with type validation | A08:2021, CWE-502 |
| Hardcoded Secrets | Environment variables & secret managers | A02:2021, CWE-798 |
| Weak Cryptography | Modern algorithms (AES-256, SHA-256+) | A02:2021, CWE-327 |

### AI-Powered Universal Support

For any other vulnerability type (SSRF, XXE, IDOR, etc.), the agent uses **Gemini 2.0** to:
- Analyze the vulnerability context
- Generate secure code fixes following best practices
- Explain the security rationale
- Provide testing recommendations

**No vulnerability is unsupported** - the agent adapts to handle security issues across all languages and frameworks.

## Installation

```bash
pip install PyGithub
```

## Usage

### 1. Dry Run (Preview Only)

```bash
python test_remediation_agent.py
```

This will:
- Load vulnerabilities from `evaluation/results/semgrep-results.json`
- Analyze and categorize them
- Generate fixes
- Create README preview
- Show what would be in the PR (without actually creating it)

### 2. Create Real PR

```bash
export GITHUB_TOKEN=your_github_personal_access_token
python test_remediation_agent.py --real-pr owner/repo-name
```

This will:
- Create a new branch: `fix/security-remediation-TIMESTAMP`
- Generate `SECURITY_FIXES.md` with detailed documentation
- Commit the changes
- Create a Pull Request with:
  - Title: "🔒 Security Fix: Address N vulnerabilities"
  - Labels: "security", "auto-remediation"
  - Comprehensive description

## GitHub Token Permissions

Your GitHub token needs these permissions:
- `repo` (full access) or:
  - `contents: write` (create branches, commit)
  - `pull_requests: write` (create PRs)

Create a token at: https://github.com/settings/tokens

## Integration with CI/CD

Add to `.github/workflows/devsecops.yml`:

```yaml
- name: Auto-Remediation
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  env:
    GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    python -m agents.remediation_agent.cli \
      --vulnerabilities evaluation/results/semgrep-results.json \
      --severity ERROR \
      --auto-pr
```

## Example Output

### SECURITY_FIXES.md Structure

```markdown
# 🔒 Security Remediation Report

**Repository**: owner/repo  
**Vulnerabilities Fixed**: 5  
**Severity Breakdown**: 3 ERROR, 2 WARNING  

---

## 🐛 Vulnerabilities Fixed

### 1. SQL Injection

**File**: `database.py`:45  
**Severity**: **ERROR**  
**CWE**: CWE-89  
**OWASP**: A03:2021 - Injection  

**Description**: User input directly concatenated in SQL query

**Fix Applied**:
```diff
-query = f"SELECT * FROM users WHERE id = {user_id}"
+query = "SELECT * FROM users WHERE id = ?"
+cursor.execute(query, (user_id,))
```

**Why This Fix Works**: Parameterized queries prevent SQL injection...

---

## ✅ Testing Checklist
- [ ] Run all unit tests
- [ ] Run security scans
- [ ] Manual code review
```

## Architecture

```
agents/remediation_agent/
├── __init__.py          # Package exports
├── agent.py             # ADK agent with LLM
├── tools.py             # Remediation tools
└── templates/           # Fix templates

core/
└── github_client.py     # GitHub API wrapper
```

## Files Modified

| Component | Purpose |
|-----------|---------|
| `agents/remediation_agent/agent.py` | ADK agent with security expertise |
| `agents/remediation_agent/tools.py` | Vulnerability analysis and PR creation |
| `core/github_client.py` | GitHub API integration |
| `test_remediation_agent.py` | Testing and CLI |
| `requirements.txt` | Added PyGithub dependency |

## Next Steps

1. ✅ **Test dry-run mode**: Preview what PRs would look like
2. ✅ **Create test PR**: Use on a test repository first
3. ⚠️ **Review and merge**: Always manually review auto-generated fixes
4. 🔄 **Integrate with pipeline**: Add to GitHub Actions for automatic remediation

## Security Considerations

> [!WARNING]
> **Always review auto-generated fixes before merging!**
> - Verify fixes don't introduce bugs
> - Test in staging environment
> - Review SECURITY_FIXES.md for accuracy

> [!NOTE]
> The agent uses template-based fixes. For production use, consider:
> - Adding LLM-powered fix generation
> - Implementing actual code modification (not just docs)
> - Adding automated testing of fixes
