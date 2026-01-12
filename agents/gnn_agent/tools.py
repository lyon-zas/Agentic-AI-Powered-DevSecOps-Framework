"""
GNN Agent Tools - Tools for test impact prediction.

Initial implementation uses heuristic-based approach.
Will be replaced with trained GNN model when data is available.
"""

import os
import re
import ast
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def get_changed_files(repo_path: str, base_branch: str = "main") -> Dict[str, Any]:
    """
    Get list of files changed in current branch compared to base.
    
    Args:
        repo_path: Path to the git repository
        base_branch: Branch to compare against (default: main)
    
    Returns:
        Dictionary with changed files information
    """
    import subprocess
    
    try:
        # Get list of changed files
        result = subprocess.run(
            ["git", "diff", "--name-only", base_branch],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return {
                "status": "error",
                "error_message": result.stderr,
                "changed_files": []
            }
        
        changed_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        
        # Categorize files
        source_files = [f for f in changed_files if _is_source_file(f)]
        test_files = [f for f in changed_files if _is_test_file(f)]
        config_files = [f for f in changed_files if _is_config_file(f)]
        
        return {
            "status": "success",
            "changed_files": changed_files,
            "source_files": source_files,
            "test_files": test_files,
            "config_files": config_files,
            "total_count": len(changed_files)
        }
        
    except Exception as e:
        logger.error(f"Error getting changed files: {e}")
        return {
            "status": "error",
            "error_message": str(e),
            "changed_files": []
        }


def build_dependency_graph(repo_path: str, changed_files: List[str]) -> Dict[str, Any]:
    """
    Build a dependency graph of the codebase focusing on changed files.
    
    Uses heuristic-based approach:
    - Parses imports to build file dependencies
    - Maps source files to test files by naming convention
    - Identifies transitive dependencies
    
    Args:
        repo_path: Path to the repository
        changed_files: List of changed file paths
    
    Returns:
        Dictionary representing the dependency graph
    """
    graph = {
        "nodes": {},  # file_path -> {type, imports, imported_by}
        "edges": [],  # [(from, to, type)]
        "file_to_tests": {},  # source_file -> [test_files]
        "test_to_files": {},  # test_file -> [source_files]
    }
    
    # Find all Python files in repo
    repo = Path(repo_path)
    all_python_files = list(repo.rglob("*.py"))
    
    # Build import graph
    for file_path in all_python_files:
        rel_path = str(file_path.relative_to(repo))
        imports = _extract_imports(file_path)
        
        is_test = _is_test_file(rel_path)
        graph["nodes"][rel_path] = {
            "type": "test" if is_test else "source",
            "imports": imports,
            "imported_by": [],
        }
        
        # Map tests to source files by convention
        if is_test:
            source_file = _get_source_for_test(rel_path)
            if source_file:
                if source_file not in graph["file_to_tests"]:
                    graph["file_to_tests"][source_file] = []
                graph["file_to_tests"][source_file].append(rel_path)
                graph["test_to_files"][rel_path] = [source_file]
    
    # Build reverse import graph (imported_by)
    for file_path, node in graph["nodes"].items():
        for imp in node["imports"]:
            imp_path = _resolve_import_to_file(imp, repo_path)
            if imp_path and imp_path in graph["nodes"]:
                graph["nodes"][imp_path]["imported_by"].append(file_path)
                graph["edges"].append((file_path, imp_path, "imports"))
    
    # Find all test files
    all_tests = [f for f in graph["nodes"] if graph["nodes"][f]["type"] == "test"]
    
    return {
        "status": "success",
        "graph": graph,
        "total_nodes": len(graph["nodes"]),
        "total_edges": len(graph["edges"]),
        "all_tests": all_tests,
        "changed_files": changed_files,
    }


def predict_impacted_tests(
    dependency_graph: Dict[str, Any],
    changed_files: List[str]
) -> Dict[str, Any]:
    """
    Predict which tests are impacted by the changed files.
    
    Uses heuristic rules:
    1. Direct mapping: test_foo.py tests foo.py
    2. Import relationship: if test imports changed file
    3. Transitive: if changed file is imported by a file that test imports
    
    Args:
        dependency_graph: Output from build_dependency_graph
        changed_files: List of changed file paths
    
    Returns:
        Dictionary with impacted tests and confidence scores
    """
    graph = dependency_graph.get("graph", {})
    all_tests = dependency_graph.get("all_tests", [])
    
    impacted_tests: Dict[str, float] = {}  # test -> confidence
    impact_reasons: Dict[str, List[str]] = {}  # test -> reasons
    
    for changed_file in changed_files:
        # Skip if it's a test file itself
        if _is_test_file(changed_file):
            impacted_tests[changed_file] = 1.0
            impact_reasons[changed_file] = ["Test file was directly modified"]
            continue
        
        # Rule 1: Direct mapping by naming convention
        related_tests = graph.get("file_to_tests", {}).get(changed_file, [])
        for test in related_tests:
            impacted_tests[test] = max(impacted_tests.get(test, 0), 0.95)
            if test not in impact_reasons:
                impact_reasons[test] = []
            impact_reasons[test].append(f"Direct mapping to {changed_file}")
        
        # Rule 2: Tests that import the changed file
        if changed_file in graph.get("nodes", {}):
            imported_by = graph["nodes"][changed_file].get("imported_by", [])
            for importer in imported_by:
                if _is_test_file(importer):
                    impacted_tests[importer] = max(impacted_tests.get(importer, 0), 0.9)
                    if importer not in impact_reasons:
                        impact_reasons[importer] = []
                    impact_reasons[importer].append(f"Imports {changed_file}")
        
        # Rule 3: Transitive dependencies (1 level)
        if changed_file in graph.get("nodes", {}):
            imported_by = graph["nodes"][changed_file].get("imported_by", [])
            for importer in imported_by:
                if importer in graph.get("nodes", {}):
                    second_level = graph["nodes"][importer].get("imported_by", [])
                    for test in second_level:
                        if _is_test_file(test):
                            impacted_tests[test] = max(impacted_tests.get(test, 0), 0.7)
                            if test not in impact_reasons:
                                impact_reasons[test] = []
                            impact_reasons[test].append(f"Transitively depends on {changed_file}")
    
    # Determine which tests can be skipped
    skip_tests = [t for t in all_tests if t not in impacted_tests]
    
    return {
        "status": "success",
        "impacted_tests": list(impacted_tests.keys()),
        "confidence_scores": impacted_tests,
        "impact_reasons": impact_reasons,
        "skip_tests": skip_tests,
        "total_tests": len(all_tests),
        "impacted_count": len(impacted_tests),
        "skip_count": len(skip_tests),
    }


def calculate_runtime_savings(
    impact_prediction: Dict[str, Any],
    avg_test_duration_seconds: float = 2.0
) -> Dict[str, Any]:
    """
    Calculate estimated runtime savings from running only impacted tests.
    
    Args:
        impact_prediction: Output from predict_impacted_tests
        avg_test_duration_seconds: Average duration per test
    
    Returns:
        Dictionary with runtime savings estimates
    """
    total_tests = impact_prediction.get("total_tests", 0)
    impacted_count = impact_prediction.get("impacted_count", 0)
    skip_count = impact_prediction.get("skip_count", 0)
    
    full_suite_time = total_tests * avg_test_duration_seconds
    optimized_time = impacted_count * avg_test_duration_seconds
    savings_seconds = skip_count * avg_test_duration_seconds
    savings_percentage = (savings_seconds / full_suite_time * 100) if full_suite_time > 0 else 0
    
    return {
        "status": "success",
        "full_suite_duration_seconds": full_suite_time,
        "optimized_duration_seconds": optimized_time,
        "savings_seconds": savings_seconds,
        "savings_percentage": round(savings_percentage, 1),
        "tests_to_run": impacted_count,
        "tests_to_skip": skip_count,
        "recommendation": _get_recommendation(savings_percentage, impacted_count, total_tests),
    }


# ===== Helper Functions =====

def _is_source_file(path: str) -> bool:
    """Check if file is a source code file."""
    extensions = {".py", ".js", ".ts", ".java", ".go", ".rs"}
    return any(path.endswith(ext) for ext in extensions) and not _is_test_file(path)


def _is_test_file(path: str) -> bool:
    """Check if file is a test file."""
    path_lower = path.lower()
    test_indicators = ["test_", "_test.", "tests/", "test/", ".test.", "_spec."]
    return any(ind in path_lower for ind in test_indicators)


def _is_config_file(path: str) -> bool:
    """Check if file is a configuration file."""
    config_patterns = [".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".env"]
    return any(path.endswith(p) for p in config_patterns)


def _extract_imports(file_path: Path) -> List[str]:
    """Extract imports from a Python file."""
    imports = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
                    
    except Exception as e:
        logger.warning(f"Could not parse imports from {file_path}: {e}")
    
    return imports


def _get_source_for_test(test_path: str) -> Optional[str]:
    """Get the source file that a test file tests (by naming convention)."""
    # test_foo.py -> foo.py
    # tests/test_foo.py -> foo.py or src/foo.py
    
    filename = os.path.basename(test_path)
    
    # Remove test prefix/suffix
    source_name = filename
    if source_name.startswith("test_"):
        source_name = source_name[5:]
    elif source_name.endswith("_test.py"):
        source_name = source_name[:-8] + ".py"
    
    return source_name if source_name != filename else None


def _resolve_import_to_file(import_name: str, repo_path: str) -> Optional[str]:
    """Try to resolve an import name to a file path."""
    # Convert module.submodule to module/submodule.py
    path = import_name.replace(".", "/") + ".py"
    full_path = os.path.join(repo_path, path)
    
    if os.path.exists(full_path):
        return path
    
    # Try __init__.py
    init_path = import_name.replace(".", "/") + "/__init__.py"
    if os.path.exists(os.path.join(repo_path, init_path)):
        return init_path
    
    return None


def _get_recommendation(savings_pct: float, impacted: int, total: int) -> str:
    """Generate a recommendation based on savings analysis."""
    if savings_pct > 50:
        return f"High optimization potential: Skip {total - impacted} tests for {savings_pct:.0f}% time savings"
    elif savings_pct > 20:
        return f"Moderate optimization: Skip {total - impacted} tests for {savings_pct:.0f}% time savings"
    elif savings_pct > 5:
        return f"Minor optimization: Run impacted tests only for {savings_pct:.0f}% savings"
    else:
        return "Low optimization potential: Consider running full test suite"
