"""
Start the DevSecOps Dashboard with iDoFT test data pre-loaded.
"""

import csv
import sys
from pathlib import Path
from datetime import datetime

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from dashboard.app import app, _pipeline_runs, _flaky_tests, _vulnerabilities, _test_predictions


def load_idoft_data(limit: int = 100):
    """Load flaky test data from iDoFT into the dashboard."""
    csv_path = Path(__file__).parent / "idoft" / "py-data.csv"
    
    if not csv_path.exists():
        print("iDoFT data not found, starting with empty data")
        return
    
    print(f"Loading iDoFT data from {csv_path}...")
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        
        for i, row in enumerate(reader):
            if i >= limit:
                break
            
            if len(row) >= 4:
                test_name = row[2].strip()
                flaky_type = row[3].strip()
                status = row[4].strip() if len(row) > 4 else 'Unknown'
                
                # Map flakiness type to probability
                type_to_prob = {
                    'OD': 0.65,
                    'OD-Vic': 0.55,
                    'OD-Brit': 0.50,
                    'NIO': 0.60,
                    'NOD': 0.45,
                    'ID': 0.40,
                }
                
                p_failure = type_to_prob.get(flaky_type, 0.35)
                
                _flaky_tests.append({
                    "test_id": f"idoft-{i}",
                    "test_name": test_name,
                    "p_failure": p_failure,
                    "total_runs": 10,
                    "failures": int(p_failure * 10),
                    "flaky_type": flaky_type,
                    "status": status,
                    "quarantined": status == "Accepted",
                })
    
    print(f"Loaded {len(_flaky_tests)} flaky tests")
    
    # Add sample pipeline runs
    _pipeline_runs.extend([
        {
            "id": "run-001",
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "trigger": "iDoFT validation",
            "branch": "main",
        },
        {
            "id": "run-002", 
            "timestamp": datetime.now().isoformat(),
            "status": "success",
            "trigger": "integration test",
            "branch": "main",
        }
    ])
    
    # Add sample test prediction
    _test_predictions.append({
        "changed_files": ["core/vector_store.py", "agents/flaky_test_agent/tools.py"],
        "impacted_tests": 15,
        "skip_tests": 35,
        "savings_percentage": 70,
        "timestamp": datetime.now().isoformat(),
    })
    
    print("Dashboard data initialized!")


if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("🚀 AI DevSecOps Dashboard")
    print("="*60)
    
    # Load data
    load_idoft_data(limit=100)
    
    print("\nStarting server at http://localhost:8080")
    print("Press Ctrl+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
