"""
Evaluation Metrics Module.

Provides metrics for evaluating security scanning effectiveness:
- Detection accuracy (TP, FP, FN, TN)
- Precision, Recall, F1-Score
- Severity classification accuracy
- Remediation quality metrics
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
from pathlib import Path
from datetime import datetime


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding."""
    id: str
    type: str  # e.g., "SQL_INJECTION", "XSS"
    severity: str  # "critical", "high", "medium", "low"
    file_path: str
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    description: str = ""
    tool: str = ""
    is_true_positive: Optional[bool] = None


@dataclass
class GroundTruth:
    """Ground truth for a benchmark dataset."""
    dataset_name: str
    vulnerabilities: List[VulnerabilityFinding]
    total_files: int
    total_loc: int  # Lines of code
    

def confusion_matrix(
    predictions: List[VulnerabilityFinding],
    ground_truth: List[VulnerabilityFinding],
    match_by: str = "file_line"  # "file_line", "file_type", "cwe"
) -> Dict[str, int]:
    """
    Calculate confusion matrix for vulnerability detection.
    
    Args:
        predictions: Findings from the scanner
        ground_truth: Known vulnerabilities
        match_by: How to match predictions to ground truth
    
    Returns:
        Dictionary with TP, FP, FN, TN counts
    """
    def get_key(v: VulnerabilityFinding) -> str:
        if match_by == "file_line":
            return f"{v.file_path}:{v.line_number}:{v.type}"
        elif match_by == "file_type":
            return f"{v.file_path}:{v.type}"
        elif match_by == "cwe":
            return f"{v.file_path}:{v.cwe_id}"
        else:
            return f"{v.file_path}:{v.type}"
    
    pred_keys = set(get_key(v) for v in predictions)
    gt_keys = set(get_key(v) for v in ground_truth)
    
    tp = len(pred_keys & gt_keys)  # True Positives
    fp = len(pred_keys - gt_keys)  # False Positives
    fn = len(gt_keys - pred_keys)  # False Negatives
    
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "predicted_total": len(predictions),
        "actual_total": len(ground_truth),
    }


def calculate_metrics(confusion: Dict[str, int]) -> Dict[str, float]:
    """
    Calculate evaluation metrics from confusion matrix.
    
    Args:
        confusion: Output from confusion_matrix()
    
    Returns:
        Dictionary with precision, recall, F1, F2 scores
    """
    tp = confusion["true_positives"]
    fp = confusion["false_positives"]
    fn = confusion["false_negatives"]
    
    # Precision: TP / (TP + FP)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # Recall (True Positive Rate): TP / (TP + FN)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # F1 Score: Harmonic mean of precision and recall
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # F2 Score: Weighted toward recall (more important in security)
    f2 = 5 * (precision * recall) / (4 * precision + recall) if (4 * precision + recall) > 0 else 0.0
    
    # False Positive Rate
    fpr = fp / (fp + tp) if (fp + tp) > 0 else 0.0
    
    # Detection Rate (same as recall)
    detection_rate = recall
    
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "f2_score": round(f2, 4),
        "false_positive_rate": round(fpr, 4),
        "detection_rate": round(detection_rate, 4),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
    }


def calculate_severity_metrics(
    predictions: List[VulnerabilityFinding],
    ground_truth: List[VulnerabilityFinding]
) -> Dict[str, float]:
    """
    Calculate severity classification accuracy.
    
    Args:
        predictions: Findings with severity classifications
        ground_truth: Known vulnerabilities with true severity
    
    Returns:
        Dictionary with severity metrics
    """
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    
    # Match predictions to ground truth
    matched = 0
    correct_severity = 0
    off_by_one = 0
    
    for pred in predictions:
        for gt in ground_truth:
            if pred.file_path == gt.file_path and pred.type == gt.type:
                matched += 1
                if pred.severity.lower() == gt.severity.lower():
                    correct_severity += 1
                else:
                    pred_level = severity_order.get(pred.severity.lower(), 0)
                    gt_level = severity_order.get(gt.severity.lower(), 0)
                    if abs(pred_level - gt_level) == 1:
                        off_by_one += 1
                break
    
    severity_accuracy = correct_severity / matched if matched > 0 else 0.0
    near_accuracy = (correct_severity + off_by_one) / matched if matched > 0 else 0.0
    
    return {
        "severity_accuracy": round(severity_accuracy, 4),
        "near_accuracy": round(near_accuracy, 4),  # Within 1 level
        "matched_findings": matched,
        "correct_severity": correct_severity,
        "off_by_one": off_by_one,
    }


def calculate_remediation_metrics(
    remediations: List[Dict[str, Any]],
    test_results: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, float]:
    """
    Calculate metrics for AI-generated remediation quality.
    
    Args:
        remediations: List of remediation attempts with results
        test_results: Optional test execution results
    
    Returns:
        Dictionary with remediation metrics
    """
    total = len(remediations)
    if total == 0:
        return {"error": "No remediations to evaluate"}
    
    valid_patches = sum(1 for r in remediations if r.get("is_valid", False))
    correct_fixes = sum(1 for r in remediations if r.get("fixes_vulnerability", False))
    build_success = sum(1 for r in remediations if r.get("build_passes", False))
    
    tests_pass = 0
    if test_results:
        tests_pass = sum(1 for t in test_results if t.get("all_passed", False))
    
    return {
        "patch_validity_rate": round(valid_patches / total, 4),
        "fix_correctness_rate": round(correct_fixes / total, 4),
        "build_success_rate": round(build_success / total, 4),
        "test_pass_rate": round(tests_pass / total, 4) if test_results else None,
        "total_remediations": total,
    }


def calculate_pipeline_metrics(
    run_data: Dict[str, Any]
) -> Dict[str, float]:
    """
    Calculate CI/CD pipeline efficiency metrics.
    
    Args:
        run_data: Pipeline execution data
    
    Returns:
        Dictionary with pipeline metrics
    """
    return {
        "total_scan_time_seconds": run_data.get("scan_time", 0),
        "tests_selected": run_data.get("tests_selected", 0),
        "tests_skipped": run_data.get("tests_skipped", 0),
        "selection_accuracy": run_data.get("selection_accuracy", 0),
        "time_saved_seconds": run_data.get("time_saved", 0),
        "time_saved_percent": run_data.get("time_saved_percent", 0),
        "flaky_tests_detected": run_data.get("flaky_detected", 0),
        "flaky_detection_accuracy": run_data.get("flaky_accuracy", 0),
    }


# ============================================================================
# ADVANCED THESIS METRICS
# ============================================================================

def calculate_defect_detection_rate(
    detected_defects: int,
    total_known_defects: int,
    total_files_scanned: int = 0
) -> Dict[str, float]:
    """
    Calculate Defect Detection Rate (DDR) / Fault Detection Rate (FDR).
    
    DDR = Number of defects detected / Total known defects
    
    Args:
        detected_defects: Number of true positives
        total_known_defects: Ground truth defect count
        total_files_scanned: Optional file count for density
    
    Returns:
        Dictionary with detection rate metrics
    """
    ddr = detected_defects / total_known_defects if total_known_defects > 0 else 0.0
    
    # Defect density (defects per file)
    density = detected_defects / total_files_scanned if total_files_scanned > 0 else 0.0
    
    return {
        "defect_detection_rate": round(ddr, 4),
        "fault_detection_rate": round(ddr, 4),  # Alias
        "detected_defects": detected_defects,
        "total_known_defects": total_known_defects,
        "defect_density": round(density, 4),
    }


def calculate_mttd_mttr(
    detection_events: List[Dict[str, Any]],
    remediation_events: List[Dict[str, Any]] = None
) -> Dict[str, float]:
    """
    Calculate Mean Time to Detect (MTTD) and Mean Time to Remediate (MTTR).
    
    MTTD = Average time from vulnerability introduction to detection
    MTTR = Average time from detection to remediation
    
    Args:
        detection_events: List of {vulnerability_id, introduced_at, detected_at}
        remediation_events: List of {vulnerability_id, detected_at, remediated_at}
    
    Returns:
        Dictionary with MTTD and MTTR in seconds
    """
    from datetime import datetime
    
    # Calculate MTTD
    mttd_values = []
    for event in detection_events:
        introduced = event.get("introduced_at")
        detected = event.get("detected_at")
        
        if introduced and detected:
            if isinstance(introduced, str):
                introduced = datetime.fromisoformat(introduced.replace('Z', '+00:00'))
            if isinstance(detected, str):
                detected = datetime.fromisoformat(detected.replace('Z', '+00:00'))
            
            time_to_detect = (detected - introduced).total_seconds()
            if time_to_detect >= 0:
                mttd_values.append(time_to_detect)
    
    mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0.0
    
    # Calculate MTTR
    mttr_values = []
    if remediation_events:
        for event in remediation_events:
            detected = event.get("detected_at")
            remediated = event.get("remediated_at")
            
            if detected and remediated:
                if isinstance(detected, str):
                    detected = datetime.fromisoformat(detected.replace('Z', '+00:00'))
                if isinstance(remediated, str):
                    remediated = datetime.fromisoformat(remediated.replace('Z', '+00:00'))
                
                time_to_remediate = (remediated - detected).total_seconds()
                if time_to_remediate >= 0:
                    mttr_values.append(time_to_remediate)
    
    mttr = sum(mttr_values) / len(mttr_values) if mttr_values else 0.0
    
    return {
        "mttd_seconds": round(mttd, 2),
        "mttd_hours": round(mttd / 3600, 2),
        "mttd_days": round(mttd / 86400, 2),
        "mttr_seconds": round(mttr, 2),
        "mttr_hours": round(mttr / 3600, 2),
        "mttr_days": round(mttr / 86400, 2),
        "detection_events_count": len(mttd_values),
        "remediation_events_count": len(mttr_values),
    }


# ============================================================================
# GENERATIVE AI / AGENT PERFORMANCE METRICS
# ============================================================================

def calculate_bleu_score(
    generated: str,
    reference: str,
    n_gram: int = 4
) -> Dict[str, float]:
    """
    Calculate BLEU Score for generated text (code, YAML, etc.).
    
    BLEU (Bilingual Evaluation Understudy) measures n-gram overlap
    between generated and reference text.
    
    Args:
        generated: Generated text (e.g., YAML config, code patch)
        reference: Human-authored reference text
        n_gram: Maximum n-gram size (default: 4)
    
    Returns:
        Dictionary with BLEU scores
    """
    from collections import Counter
    import math
    
    def get_ngrams(text: str, n: int) -> List[Tuple[str, ...]]:
        tokens = text.split()
        return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]
    
    def modified_precision(gen_tokens: List[str], ref_tokens: List[str], n: int) -> float:
        gen_ngrams = get_ngrams(' '.join(gen_tokens), n)
        ref_ngrams = get_ngrams(' '.join(ref_tokens), n)
        
        if not gen_ngrams:
            return 0.0
        
        gen_counter = Counter(gen_ngrams)
        ref_counter = Counter(ref_ngrams)
        
        clipped_count = sum(min(gen_counter[ng], ref_counter.get(ng, 0)) for ng in gen_counter)
        total_count = sum(gen_counter.values())
        
        return clipped_count / total_count if total_count > 0 else 0.0
    
    gen_tokens = generated.split()
    ref_tokens = reference.split()
    
    if not gen_tokens or not ref_tokens:
        return {"bleu_score": 0.0, "bleu_1": 0.0, "bleu_2": 0.0, "bleu_3": 0.0, "bleu_4": 0.0}
    
    # Calculate precision for each n-gram
    precisions = []
    bleu_scores = {}
    
    for n in range(1, n_gram + 1):
        p = modified_precision(gen_tokens, ref_tokens, n)
        precisions.append(p)
        bleu_scores[f"bleu_{n}"] = round(p, 4)
    
    # Brevity penalty
    bp = 1.0 if len(gen_tokens) >= len(ref_tokens) else math.exp(1 - len(ref_tokens) / len(gen_tokens))
    
    # Geometric mean of precisions
    if all(p > 0 for p in precisions):
        log_avg = sum(math.log(p) for p in precisions) / len(precisions)
        bleu = bp * math.exp(log_avg)
    else:
        bleu = 0.0
    
    bleu_scores["bleu_score"] = round(bleu, 4)
    bleu_scores["brevity_penalty"] = round(bp, 4)
    
    return bleu_scores


def calculate_edit_distance(
    generated: str,
    reference: str,
    normalize: bool = True
) -> Dict[str, float]:
    """
    Calculate Normalized Edit Distance (Levenshtein Distance).
    
    Lower values indicate higher similarity.
    
    Args:
        generated: Generated text
        reference: Reference text
        normalize: Whether to normalize by max length
    
    Returns:
        Dictionary with edit distance metrics
    """
    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    # Calculate at character level
    char_distance = levenshtein(generated, reference)
    
    # Calculate at token/line level
    gen_lines = generated.split('\n')
    ref_lines = reference.split('\n')
    line_distance = levenshtein('\n'.join(gen_lines), '\n'.join(ref_lines))
    
    max_len = max(len(generated), len(reference))
    normalized = char_distance / max_len if max_len > 0 else 0.0
    
    # Similarity (inverse)
    similarity = 1.0 - normalized
    
    return {
        "edit_distance": char_distance,
        "normalized_edit_distance": round(normalized, 4),
        "similarity": round(similarity, 4),
        "line_edit_distance": line_distance,
        "generated_length": len(generated),
        "reference_length": len(reference),
    }


def calculate_token_f1(
    generated: str,
    reference: str,
    key_tokens: List[str] = None
) -> Dict[str, float]:
    """
    Calculate Token-level F1 Score for generated configurations.
    
    Measures presence of key elements like jobs, steps, env variables in YAML.
    
    Args:
        generated: Generated configuration text
        reference: Reference configuration text
        key_tokens: Optional list of key tokens to check for
    
    Returns:
        Dictionary with token-level precision, recall, F1
    """
    import re
    
    # Default key tokens for CI/CD configurations
    if key_tokens is None:
        key_tokens = [
            "name:", "on:", "jobs:", "steps:", "runs-on:", "uses:", "with:",
            "env:", "run:", "if:", "secrets.", "needs:", "strategy:", "matrix:",
            "container:", "services:", "outputs:", "inputs:", "permissions:",
        ]
    
    def tokenize(text: str) -> set:
        # Extract significant tokens
        tokens = set()
        
        # Add key configuration tokens
        for key in key_tokens:
            if key in text:
                tokens.add(key)
        
        # Add variable names and values
        var_pattern = r'\$\{\{[^}]+\}\}'
        tokens.update(re.findall(var_pattern, text))
        
        # Add action references
        action_pattern = r'uses:\s*[\w\-\./@]+'
        tokens.update(re.findall(action_pattern, text))
        
        return tokens
    
    gen_tokens = tokenize(generated)
    ref_tokens = tokenize(reference)
    
    if not ref_tokens:
        return {"token_f1": 0.0, "token_precision": 0.0, "token_recall": 0.0}
    
    true_positives = len(gen_tokens & ref_tokens)
    false_positives = len(gen_tokens - ref_tokens)
    false_negatives = len(ref_tokens - gen_tokens)
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "token_f1": round(f1, 4),
        "token_precision": round(precision, 4),
        "token_recall": round(recall, 4),
        "matched_tokens": true_positives,
        "missing_tokens": false_negatives,
        "extra_tokens": false_positives,
    }


def calculate_success_rate(
    generations: List[Dict[str, Any]]
) -> Dict[str, float]:
    """
    Calculate Success Rate (SR) for autonomously generated outputs.
    
    Success Rate = Percentage of generated outputs that:
    - Are syntactically valid
    - Are executable/parseable
    - Meet all constraints
    - Require no human intervention
    
    Args:
        generations: List of generation results with status flags
        
    Returns:
        Dictionary with success rate metrics
    """
    if not generations:
        return {"success_rate": 0.0, "total_generations": 0}
    
    total = len(generations)
    
    # Count different success criteria
    syntactically_valid = sum(1 for g in generations if g.get("is_valid_syntax", False))
    executable = sum(1 for g in generations if g.get("is_executable", False))
    meets_constraints = sum(1 for g in generations if g.get("meets_constraints", False))
    no_human_intervention = sum(1 for g in generations if g.get("no_human_edit", False))
    
    # Full success (all criteria met)
    full_success = sum(1 for g in generations if (
        g.get("is_valid_syntax", False) and
        g.get("is_executable", False) and
        g.get("meets_constraints", False) and
        g.get("no_human_edit", False)
    ))
    
    return {
        "success_rate": round(full_success / total, 4),
        "syntax_validity_rate": round(syntactically_valid / total, 4),
        "executability_rate": round(executable / total, 4),
        "constraint_satisfaction_rate": round(meets_constraints / total, 4),
        "autonomous_rate": round(no_human_intervention / total, 4),
        "full_success_count": full_success,
        "total_generations": total,
    }


def calculate_generative_metrics(
    generated_outputs: List[Dict[str, Any]],
    reference_outputs: List[str] = None
) -> Dict[str, Any]:
    """
    Calculate all generative AI metrics for agent outputs.
    
    Aggregates BLEU, Edit Distance, Token F1, and Success Rate.
    
    Args:
        generated_outputs: List of {text, reference, is_valid_syntax, ...}
        reference_outputs: Optional list of reference texts
    
    Returns:
        Comprehensive generative metrics
    """
    if not generated_outputs:
        return {"error": "No outputs to evaluate"}
    
    bleu_scores = []
    edit_distances = []
    token_f1s = []
    
    for i, gen in enumerate(generated_outputs):
        generated_text = gen.get("text", "")
        reference_text = gen.get("reference", "")
        
        if reference_outputs and i < len(reference_outputs):
            reference_text = reference_outputs[i]
        
        if generated_text and reference_text:
            bleu_scores.append(calculate_bleu_score(generated_text, reference_text)["bleu_score"])
            edit_distances.append(calculate_edit_distance(generated_text, reference_text)["normalized_edit_distance"])
            token_f1s.append(calculate_token_f1(generated_text, reference_text)["token_f1"])
    
    success_metrics = calculate_success_rate(generated_outputs)
    
    return {
        "avg_bleu_score": round(sum(bleu_scores) / len(bleu_scores), 4) if bleu_scores else 0.0,
        "avg_edit_distance": round(sum(edit_distances) / len(edit_distances), 4) if edit_distances else 0.0,
        "avg_token_f1": round(sum(token_f1s) / len(token_f1s), 4) if token_f1s else 0.0,
        "success_rate": success_metrics["success_rate"],
        "samples_evaluated": len(bleu_scores),
        "detailed_success": success_metrics,
    }




class EvaluationReport:
    """
    Comprehensive evaluation report for thesis documentation.
    """
    
    def __init__(self, dataset_name: str, tool_name: str):
        self.dataset_name = dataset_name
        self.tool_name = tool_name
        self.timestamp = datetime.now().isoformat()
        self.detection_metrics: Dict[str, Any] = {}
        self.severity_metrics: Dict[str, Any] = {}
        self.remediation_metrics: Dict[str, Any] = {}
        self.pipeline_metrics: Dict[str, Any] = {}
        self.raw_findings: List[Dict[str, Any]] = []
    
    def add_detection_results(
        self,
        predictions: List[VulnerabilityFinding],
        ground_truth: List[VulnerabilityFinding]
    ):
        """Add detection results to the report."""
        confusion = confusion_matrix(predictions, ground_truth)
        self.detection_metrics = calculate_metrics(confusion)
        self.severity_metrics = calculate_severity_metrics(predictions, ground_truth)
        self.raw_findings = [vars(p) for p in predictions]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "dataset": self.dataset_name,
            "tool": self.tool_name,
            "timestamp": self.timestamp,
            "detection": self.detection_metrics,
            "severity": self.severity_metrics,
            "remediation": self.remediation_metrics,
            "pipeline": self.pipeline_metrics,
            "findings_count": len(self.raw_findings),
        }
    
    def save(self, output_dir: str = "evaluation/results"):
        """Save report to JSON file."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        filename = f"{self.dataset_name}_{self.tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = output_path / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        
        return str(filepath)
    
    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            f"=" * 60,
            f"EVALUATION REPORT",
            f"=" * 60,
            f"Dataset: {self.dataset_name}",
            f"Tool: {self.tool_name}",
            f"Timestamp: {self.timestamp}",
            f"",
            f"DETECTION METRICS:",
            f"  Precision: {self.detection_metrics.get('precision', 'N/A')}",
            f"  Recall: {self.detection_metrics.get('recall', 'N/A')}",
            f"  F1 Score: {self.detection_metrics.get('f1_score', 'N/A')}",
            f"  True Positives: {self.detection_metrics.get('true_positives', 0)}",
            f"  False Positives: {self.detection_metrics.get('false_positives', 0)}",
            f"  False Negatives: {self.detection_metrics.get('false_negatives', 0)}",
            f"",
            f"SEVERITY CLASSIFICATION:",
            f"  Accuracy: {self.severity_metrics.get('severity_accuracy', 'N/A')}",
            f"  Near Accuracy (±1): {self.severity_metrics.get('near_accuracy', 'N/A')}",
            f"=" * 60,
        ]
        return "\n".join(lines)


def compare_tools(reports: List[EvaluationReport]) -> Dict[str, Any]:
    """
    Compare evaluation results across multiple tools.
    
    Args:
        reports: List of evaluation reports
    
    Returns:
        Comparison summary
    """
    comparison = {
        "tools": [],
        "best_precision": {"tool": "", "value": 0},
        "best_recall": {"tool": "", "value": 0},
        "best_f1": {"tool": "", "value": 0},
        "lowest_fpr": {"tool": "", "value": 1.0},
    }
    
    for report in reports:
        tool_data = {
            "name": report.tool_name,
            "precision": report.detection_metrics.get("precision", 0),
            "recall": report.detection_metrics.get("recall", 0),
            "f1_score": report.detection_metrics.get("f1_score", 0),
            "false_positive_rate": report.detection_metrics.get("false_positive_rate", 1.0),
        }
        comparison["tools"].append(tool_data)
        
        if tool_data["precision"] > comparison["best_precision"]["value"]:
            comparison["best_precision"] = {"tool": report.tool_name, "value": tool_data["precision"]}
        if tool_data["recall"] > comparison["best_recall"]["value"]:
            comparison["best_recall"] = {"tool": report.tool_name, "value": tool_data["recall"]}
        if tool_data["f1_score"] > comparison["best_f1"]["value"]:
            comparison["best_f1"] = {"tool": report.tool_name, "value": tool_data["f1_score"]}
        if tool_data["false_positive_rate"] < comparison["lowest_fpr"]["value"]:
            comparison["lowest_fpr"] = {"tool": report.tool_name, "value": tool_data["false_positive_rate"]}
    
    return comparison
