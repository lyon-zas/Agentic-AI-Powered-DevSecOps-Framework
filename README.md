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
├── dashboard/              # Developer Dashboard UI
└── tests/                  # Test suite
```

## Documentation

- [Implementation Plan](docs/implementation_plan.md)
- [API Reference](docs/api_reference.md)
- [Agent Guide](docs/agent_guide.md)

## License

MIT License
