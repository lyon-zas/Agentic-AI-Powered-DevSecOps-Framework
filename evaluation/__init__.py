"""
Thesis Evaluation Module.

This module provides tools for evaluating the Agentic AI-Powered DevSecOps
Framework against international benchmark datasets like OWASP WebGoat.
"""

from .metrics import (
    calculate_metrics,
    confusion_matrix,
    calculate_severity_metrics,
    calculate_remediation_metrics,
    calculate_pipeline_metrics,
    # Advanced thesis metrics
    calculate_defect_detection_rate,
    calculate_mttd_mttr,
    calculate_bleu_score,
    calculate_edit_distance,
    calculate_token_f1,
    calculate_success_rate,
    calculate_generative_metrics,
    # Classes
    EvaluationReport,
    VulnerabilityFinding,
    compare_tools,
)
from .runner import EvaluationRunner
from .datasets import (
    BenchmarkDataset,
    WebGoatDataset,
    DVWADataset,
    JuiceShopDataset,
    OWASPBenchmarkDataset,
    get_dataset,
    list_datasets,
    AVAILABLE_DATASETS,
)

__all__ = [
    # Core metrics
    "calculate_metrics",
    "confusion_matrix",
    "calculate_severity_metrics",
    "calculate_remediation_metrics",
    "calculate_pipeline_metrics",
    # Advanced metrics
    "calculate_defect_detection_rate",
    "calculate_mttd_mttr",
    "calculate_bleu_score",
    "calculate_edit_distance",
    "calculate_token_f1",
    "calculate_success_rate",
    "calculate_generative_metrics",
    # Classes
    "EvaluationReport",
    "VulnerabilityFinding",
    "compare_tools",
    "EvaluationRunner",
    # Datasets
    "BenchmarkDataset",
    "WebGoatDataset",
    "DVWADataset",
    "JuiceShopDataset",
    "OWASPBenchmarkDataset",
    "get_dataset",
    "list_datasets",
    "AVAILABLE_DATASETS",
]

