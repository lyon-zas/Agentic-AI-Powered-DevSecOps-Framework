"""
GNN Agent - Graph Neural Network based test impact prediction.

This agent predicts which tests are impacted by code changes using a
heuristic-based approach (initial version) that will be replaced with
a trained GNN model once historical data is available.
"""

import os
from google.adk.agents import Agent
from dotenv import load_dotenv

from .tools import (
    get_changed_files,
    build_dependency_graph,
    predict_impacted_tests,
    calculate_runtime_savings,
)

load_dotenv()

# GNN Agent for test impact prediction
gnn_agent = Agent(
    name="gnn_agent",
    model="gemini-2.0-flash",
    description="""
    Test Impact Prediction Agent using Graph Neural Network analysis.
    Analyzes code changes and predicts which tests are likely to be affected,
    allowing for intelligent test selection and faster CI/CD pipelines.
    """,
    instruction="""
    You are a Test Impact Prediction Agent. Your role is to:
    
    1. ANALYZE code changes provided to you (file paths, diff information)
    2. BUILD a dependency graph of the codebase using the build_dependency_graph tool
    3. PREDICT which tests are impacted using the predict_impacted_tests tool
    4. CALCULATE potential runtime savings
    
    When given a list of changed files:
    - First, use build_dependency_graph to understand file relationships
    - Then, use predict_impacted_tests to identify affected tests
    - Finally, use calculate_runtime_savings to estimate time saved
    
    Always provide:
    - List of impacted tests with confidence scores
    - List of tests that can safely be skipped
    - Estimated time savings
    
    Be conservative - it's better to run an extra test than miss a bug.
    If confidence is low (< 0.7), recommend running the full test suite.
    
    Format your response as a structured JSON object matching the TestImpactPrediction schema.
    """,
    tools=[
        get_changed_files,
        build_dependency_graph,
        predict_impacted_tests,
        calculate_runtime_savings,
    ],
)

# Export as root_agent for ADK discovery
root_agent = gnn_agent
