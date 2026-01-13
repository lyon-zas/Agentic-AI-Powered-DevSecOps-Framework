# Agentic-AI-DevSecOps-Framework

An intelligent DevSecOps framework powered by Google ADK agents for security analysis, test optimization, and CI/CD automation.

## Features

- 🔍 **GNN-Powered Test Impact Prediction** - Predicts which tests are affected by code changes
- 🧪 **Flaky Test Management** - Bayesian tracking, LLM log analysis, auto-quarantine
- 🛡️ **Security Scanning Agents** - SAST, DAST, SCA, IAST analysis
- 📊 **Test Coverage Analysis** - Smart coverage recommendations
- 🚀 **CI/CD Integration** - GitHub Actions workflows

## Quick Start

```bash
# Clone and setup
cd Agentic-AI-devsecops-framework
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Set up environment
cp config/.env.example .env
# Edit .env with your API keys

# Run ADK web UI
cd agents/orchestrator
adk web
```

## Project Structure

```
├── agents/                 # ADK Agent Packages
│   ├── orchestrator/       # Root agent
│   ├── gnn_agent/          # Test impact prediction
│   ├── flaky_test_agent/   # Flaky test management
│   ├── sast_agent/         # Static analysis
│   ├── dast_agent/         # Dynamic analysis
│   └── sca_agent/          # Dependency scanning
├── core/                   # Core components
├── integrations/           # External tool integrations
├── models/                 # ML models (GNN, Bayesian)
├── evaluation/             # Thesis Evaluation Framework
│   ├── datasets.py         # Benchmark definitions
│   ├── metrics.py          # Thesis metrics (DDR, MTTD, BLEU)
│   └── runner.py           # Evaluation orchestrator
├── dashboard/              # Developer Dashboard UI
└── tests/                  # Test suite
```

## 🎓 Thesis Evaluation

This framework includes a comprehensive evaluation module for thesis research.

### Evaluating on GitHub Actions (Recommended)

1. Go to **Actions** → **Thesis Evaluation Pipeline**
2. Click **Run workflow**
3. Select a benchmark dataset:
   - `webgoat`: OWASP WebGoat (Java)
   - `dvwa`: Damn Vulnerable Web App (PHP)
   - `juice-shop`: OWASP Juice Shop (JS)
   - `all`: Run all benchmarks
4. Download the artifacts for detailed JSON reports.

### Evaluating Locally

To evaluate on a specific dataset (e.g., WebGoat):

```bash
# Evaluate WebGoat
python -m evaluation.runner --dataset webgoat

# Evaluate all datasets with specific tools
python -m evaluation.runner --all --tools semgrep sast_agent
```

**Note**: Datasets are cloned to `evaluation/datasets/` and are excluded from git.

## Documentation

- [Implementation Plan](docs/implementation_plan.md)
- [API Reference](docs/api_reference.md)
- [Agent Guide](docs/agent_guide.md)

## License

MIT License
