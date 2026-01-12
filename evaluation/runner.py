"""
Evaluation Runner Module.

Orchestrates running security scans on benchmark datasets
and collecting results for thesis evaluation.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from .datasets import BenchmarkDataset, get_dataset, AVAILABLE_DATASETS
from .metrics import (
    EvaluationReport,
    VulnerabilityFinding,
    confusion_matrix,
    calculate_metrics,
    compare_tools,
)

logger = logging.getLogger(__name__)


class EvaluationRunner:
    """
    Runs security evaluations on benchmark datasets.
    
    Supports both baseline tools and the AI-powered framework.
    """
    
    def __init__(
        self,
        output_dir: str = "evaluation/results",
        datasets_dir: str = "evaluation/datasets"
    ):
        self.output_dir = Path(output_dir)
        self.datasets_dir = Path(datasets_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[EvaluationReport] = []
    
    def clone_dataset(self, dataset_name: str) -> str:
        """
        Clone a benchmark dataset from GitHub.
        
        Args:
            dataset_name: Name of the dataset
        
        Returns:
            Local path to the cloned repository
        """
        dataset = get_dataset(dataset_name)
        local_path = self.datasets_dir / dataset_name
        
        if local_path.exists():
            logger.info(f"Dataset {dataset_name} already exists at {local_path}")
            return str(local_path)
        
        logger.info(f"Cloning {dataset_name} from {dataset.url}...")
        
        result = subprocess.run(
            ["git", "clone", dataset.url, str(local_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone {dataset_name}: {result.stderr}")
        
        logger.info(f"Successfully cloned {dataset_name} to {local_path}")
        return str(local_path)
    
    def run_semgrep(
        self,
        target_path: str,
        config: str = "auto"
    ) -> Dict[str, Any]:
        """
        Run Semgrep scan as baseline.
        
        Args:
            target_path: Path to scan
            config: Semgrep config (auto, p/python, p/java, etc.)
        
        Returns:
            Scan results
        """
        logger.info(f"Running Semgrep on {target_path}...")
        start_time = time.time()
        
        # Find semgrep in venv
        python_dir = os.path.dirname(sys.executable)
        semgrep_path = os.path.join(python_dir, "semgrep")
        if not os.path.exists(semgrep_path):
            semgrep_path = "semgrep"
        
        result = subprocess.run(
            [semgrep_path, "scan", "--config", config, "--json", target_path],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        elapsed = time.time() - start_time
        
        try:
            output = json.loads(result.stdout) if result.stdout else {}
            findings = output.get("results", [])
            
            vulnerabilities = []
            for finding in findings:
                vulnerabilities.append(VulnerabilityFinding(
                    id=finding.get("check_id", ""),
                    type=finding.get("check_id", "").split(".")[-1] if finding.get("check_id") else "",
                    severity=finding.get("extra", {}).get("severity", "medium").lower(),
                    file_path=finding.get("path", ""),
                    line_number=finding.get("start", {}).get("line"),
                    cwe_id=finding.get("extra", {}).get("metadata", {}).get("cwe", ""),
                    description=finding.get("extra", {}).get("message", ""),
                    tool="semgrep",
                ))
            
            return {
                "status": "success",
                "tool": "semgrep",
                "elapsed_seconds": elapsed,
                "total_findings": len(vulnerabilities),
                "findings": vulnerabilities,
            }
        except Exception as e:
            return {
                "status": "error",
                "tool": "semgrep",
                "error": str(e),
            }
    
    def run_sast_agent(
        self,
        target_path: str
    ) -> Dict[str, Any]:
        """
        Run AI-powered SAST agent.
        
        Args:
            target_path: Path to scan
        
        Returns:
            Scan results
        """
        logger.info(f"Running SAST Agent on {target_path}...")
        start_time = time.time()
        
        try:
            from agents.sast_agent.tools import run_semgrep_scan, parse_semgrep_results
            
            raw_result = run_semgrep_scan(target_path, config="auto")
            if raw_result.get("status") == "success":
                parsed = parse_semgrep_results(raw_result.get("raw_output", {}))
                elapsed = time.time() - start_time
                
                vulnerabilities = []
                for v in parsed.get("vulnerabilities", []):
                    vulnerabilities.append(VulnerabilityFinding(
                        id=v.get("id", ""),
                        type=v.get("type", ""),
                        severity=v.get("severity", "medium").lower(),
                        file_path=v.get("file_path", ""),
                        line_number=v.get("start_line"),
                        cwe_id=v.get("cwe_id", ""),
                        description=v.get("description", ""),
                        tool="sast_agent",
                    ))
                
                return {
                    "status": "success",
                    "tool": "sast_agent",
                    "elapsed_seconds": elapsed,
                    "total_findings": len(vulnerabilities),
                    "findings": vulnerabilities,
                }
            else:
                return {
                    "status": "error",
                    "tool": "sast_agent",
                    "error": raw_result.get("message", "Unknown error"),
                }
        except Exception as e:
            return {
                "status": "error",
                "tool": "sast_agent",
                "error": str(e),
            }
    
    def run_sca_agent(
        self,
        target_path: str
    ) -> Dict[str, Any]:
        """
        Run AI-powered SCA agent.
        
        Args:
            target_path: Path to scan
        
        Returns:
            Scan results with dependency vulnerabilities
        """
        logger.info(f"Running SCA Agent on {target_path}...")
        start_time = time.time()
        
        try:
            from agents.sca_agent.tools import run_snyk_scan, run_pip_audit, run_npm_audit
            
            # Try different SCA tools based on project type
            results = {}
            
            # Python dependencies
            if os.path.exists(os.path.join(target_path, "requirements.txt")):
                results["pip_audit"] = run_pip_audit(target_path)
            
            # JavaScript dependencies
            if os.path.exists(os.path.join(target_path, "package.json")):
                results["npm_audit"] = run_npm_audit(target_path)
            
            # Snyk (if configured)
            if os.getenv("SNYK_TOKEN"):
                results["snyk"] = run_snyk_scan(target_path)
            
            elapsed = time.time() - start_time
            
            return {
                "status": "success",
                "tool": "sca_agent",
                "elapsed_seconds": elapsed,
                "results": results,
            }
        except Exception as e:
            return {
                "status": "error",
                "tool": "sca_agent",
                "error": str(e),
            }
    
    def evaluate_dataset(
        self,
        dataset_name: str,
        tools: List[str] = None,
        save_results: bool = True
    ) -> Dict[str, EvaluationReport]:
        """
        Run full evaluation on a benchmark dataset.
        
        Args:
            dataset_name: Name of the benchmark dataset
            tools: List of tools to run (default: all)
            save_results: Whether to save results to files
        
        Returns:
            Dictionary of evaluation reports by tool
        """
        if tools is None:
            tools = ["semgrep", "sast_agent"]
        
        # Get dataset
        dataset = get_dataset(dataset_name)
        
        # Clone if needed
        if not dataset.is_available():
            local_path = self.clone_dataset(dataset_name)
            dataset.local_path = local_path
        
        ground_truth_findings = [
            VulnerabilityFinding(
                id=f"{v.vulnerability_type}_{i}",
                type=v.vulnerability_type,
                severity=v.severity,
                file_path=v.file_path,
                cwe_id=v.cwe_id,
                description=v.description,
            )
            for i, v in enumerate(dataset.get_ground_truth())
        ]
        
        reports = {}
        
        for tool in tools:
            logger.info(f"Running {tool} on {dataset_name}...")
            
            if tool == "semgrep":
                result = self.run_semgrep(dataset.get_scan_path())
            elif tool == "sast_agent":
                result = self.run_sast_agent(dataset.get_scan_path())
            else:
                logger.warning(f"Unknown tool: {tool}")
                continue
            
            if result.get("status") == "success":
                report = EvaluationReport(dataset_name, tool)
                report.add_detection_results(
                    result.get("findings", []),
                    ground_truth_findings
                )
                report.pipeline_metrics = {
                    "scan_time_seconds": result.get("elapsed_seconds", 0),
                }
                
                if save_results:
                    filepath = report.save(str(self.output_dir))
                    logger.info(f"Saved report to {filepath}")
                
                reports[tool] = report
                self.results.append(report)
        
        return reports
    
    def run_full_evaluation(
        self,
        datasets: List[str] = None,
        tools: List[str] = None
    ) -> Dict[str, Any]:
        """
        Run evaluation across all datasets and tools.
        
        Args:
            datasets: List of dataset names (default: all available)
            tools: List of tools to run
        
        Returns:
            Summary of all evaluations
        """
        if datasets is None:
            datasets = list(AVAILABLE_DATASETS.keys())
        
        all_reports = {}
        
        for dataset_name in datasets:
            logger.info(f"\n{'='*60}")
            logger.info(f"Evaluating dataset: {dataset_name}")
            logger.info(f"{'='*60}")
            
            try:
                reports = self.evaluate_dataset(dataset_name, tools)
                all_reports[dataset_name] = reports
            except Exception as e:
                logger.error(f"Failed to evaluate {dataset_name}: {e}")
                all_reports[dataset_name] = {"error": str(e)}
        
        # Generate comparison
        if self.results:
            comparison = compare_tools(self.results)
        else:
            comparison = {}
        
        # Save summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "datasets_evaluated": datasets,
            "tools_used": tools,
            "total_reports": len(self.results),
            "comparison": comparison,
        }
        
        summary_path = self.output_dir / f"evaluation_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"\nEvaluation complete. Summary saved to {summary_path}")
        
        return summary
    
    def print_summary(self):
        """Print summary of all evaluation results."""
        if not self.results:
            print("No evaluation results available.")
            return
        
        print("\n" + "=" * 70)
        print("EVALUATION SUMMARY")
        print("=" * 70)
        
        for report in self.results:
            print(f"\n{report.dataset_name} - {report.tool_name}")
            print("-" * 40)
            print(f"  Precision: {report.detection_metrics.get('precision', 'N/A')}")
            print(f"  Recall: {report.detection_metrics.get('recall', 'N/A')}")
            print(f"  F1 Score: {report.detection_metrics.get('f1_score', 'N/A')}")
            print(f"  True Positives: {report.detection_metrics.get('true_positives', 0)}")
            print(f"  False Positives: {report.detection_metrics.get('false_positives', 0)}")


def main():
    """Run evaluation from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run thesis evaluation")
    parser.add_argument("--dataset", "-d", help="Dataset to evaluate (webgoat, dvwa, etc.)")
    parser.add_argument("--all", action="store_true", help="Evaluate all datasets")
    parser.add_argument("--tools", "-t", nargs="+", default=["semgrep", "sast_agent"], 
                        help="Tools to run")
    parser.add_argument("--output", "-o", default="evaluation/results", help="Output directory")
    
    args = parser.parse_args()
    
    runner = EvaluationRunner(output_dir=args.output)
    
    if args.all:
        runner.run_full_evaluation(tools=args.tools)
    elif args.dataset:
        runner.evaluate_dataset(args.dataset, tools=args.tools)
    else:
        parser.print_help()
    
    runner.print_summary()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
