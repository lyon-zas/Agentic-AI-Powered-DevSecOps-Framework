"""
Developer Dashboard - FastAPI web application for DevSecOps results.

Provides:
- Real-time agent status
- Vulnerability reports
- Test impact predictions
- Flaky test management
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pathlib import Path
from typing import Dict, Any, List
import json
from datetime import datetime

# Create FastAPI app
app = FastAPI(
    title="AI DevSecOps Dashboard",
    description="Developer Dashboard for Agentic DevSecOps Framework",
    version="0.1.0",
)

# Set up templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# In-memory storage for demo (would be database in production)
_pipeline_runs: List[Dict[str, Any]] = []
_vulnerabilities: List[Dict[str, Any]] = []
_flaky_tests: List[Dict[str, Any]] = []
_test_predictions: List[Dict[str, Any]] = []


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Dashboard home page."""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "AI DevSecOps Dashboard",
        "pipeline_runs": _pipeline_runs[-10:],  # Last 10 runs
        "stats": get_dashboard_stats(),
    })


@app.get("/api/stats")
async def api_stats():
    """Get dashboard statistics."""
    return get_dashboard_stats()


@app.get("/api/vulnerabilities")
async def api_vulnerabilities(severity: str = None, limit: int = 50):
    """Get vulnerability list with optional filtering."""
    vulns = _vulnerabilities
    if severity:
        vulns = [v for v in vulns if v.get("severity") == severity]
    return {"vulnerabilities": vulns[:limit], "total": len(vulns)}


@app.get("/api/flaky-tests")
async def api_flaky_tests(threshold: float = 0.3):
    """Get flaky tests above threshold."""
    flaky = [t for t in _flaky_tests if t.get("p_failure", 0) > threshold]
    return {
        "flaky_tests": flaky,
        "total_flaky": len(flaky),
        "total_tracked": len(_flaky_tests),
    }


@app.get("/api/test-predictions")
async def api_test_predictions(limit: int = 10):
    """Get recent test impact predictions."""
    return {"predictions": _test_predictions[:limit]}


@app.post("/api/pipeline/run")
async def api_trigger_run(request: Request):
    """Trigger a new pipeline run."""
    data = await request.json()
    run = {
        "id": f"run-{len(_pipeline_runs) + 1}",
        "timestamp": datetime.now().isoformat(),
        "status": "pending",
        "trigger": data.get("trigger", "manual"),
        "branch": data.get("branch", "main"),
    }
    _pipeline_runs.append(run)
    return run


@app.post("/api/vulnerabilities")
async def api_add_vulnerability(request: Request):
    """Add a new vulnerability (from agent)."""
    vuln = await request.json()
    vuln["id"] = f"VULN-{len(_vulnerabilities) + 1}"
    vuln["timestamp"] = datetime.now().isoformat()
    _vulnerabilities.append(vuln)
    return vuln


@app.post("/api/flaky-tests")
async def api_update_flaky_test(request: Request):
    """Update flaky test data (from agent)."""
    data = await request.json()
    # Update or add
    test_id = data.get("test_id")
    for i, t in enumerate(_flaky_tests):
        if t.get("test_id") == test_id:
            _flaky_tests[i] = data
            return data
    _flaky_tests.append(data)
    return data


@app.post("/api/test-predictions")
async def api_add_prediction(request: Request):
    """Add test impact prediction (from GNN agent)."""
    prediction = await request.json()
    prediction["timestamp"] = datetime.now().isoformat()
    _test_predictions.insert(0, prediction)
    # Keep only last 100
    if len(_test_predictions) > 100:
        _test_predictions.pop()
    return prediction


@app.post("/api/flaky-tests/{test_id}/quarantine")
async def api_quarantine_test(test_id: str):
    """Quarantine a flaky test."""
    for t in _flaky_tests:
        if t.get("test_id") == test_id:
            t["quarantined"] = True
            t["quarantined_at"] = datetime.now().isoformat()
            return {"status": "success", "test": t}
    raise HTTPException(status_code=404, detail="Test not found")


def get_dashboard_stats() -> Dict[str, Any]:
    """Calculate dashboard statistics."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in _vulnerabilities:
        sev = v.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    flaky_count = len([t for t in _flaky_tests if t.get("p_failure", 0) > 0.3])
    quarantined_count = len([t for t in _flaky_tests if t.get("quarantined")])
    
    return {
        "total_runs": len(_pipeline_runs),
        "vulnerabilities": {
            "total": len(_vulnerabilities),
            "by_severity": severity_counts,
        },
        "flaky_tests": {
            "total_tracked": len(_flaky_tests),
            "flaky": flaky_count,
            "quarantined": quarantined_count,
        },
        "test_predictions": len(_test_predictions),
        "last_updated": datetime.now().isoformat(),
    }


def get_vulnerabilities():
    """Get all vulnerabilities."""
    return _vulnerabilities


def run_dashboard(host: str = "0.0.0.0", port: int = 8080):
    """Run the dashboard server."""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dashboard()
