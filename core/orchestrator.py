"""
Security Orchestrator - Manages component interactions and policy enforcement
through a message bus architecture with conflict resolution strategies.

Adapted from ai-devsecops-framework with ADK integration patterns.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


class ConflictResolutionStrategy(Enum):
    """Strategy for resolving conflicts between security signals."""
    CONSERVATIVE = "conservative"      # Apply strictest measure
    MAJORITY_BASED = "majority"         # Follow majority decision
    CONFIDENCE_WEIGHTED = "confidence"  # Use weighted confidence scores


@dataclass
class SecuritySignal:
    """A security signal from a detection component."""
    component: str
    threat_type: str
    confidence: float
    severity: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyAction:
    """An action to be taken based on security signals."""
    action_type: str
    target: str
    parameters: Dict[str, Any]
    confidence: float


class SecurityOrchestrator:
    """
    Orchestrates security components and resolves conflicts between
    different security signals using configurable strategies.
    
    This integrates with ADK agents by processing their output signals
    and determining appropriate responses.
    """
    
    def __init__(
        self, 
        strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.CONFIDENCE_WEIGHTED
    ):
        self.strategy = strategy
        self.active_signals: List[SecuritySignal] = []
        self.policy_actions: List[PolicyAction] = []
        self.component_weights = {
            "gnn_agent": 0.85,
            "sast_agent": 0.8,
            "dast_agent": 0.75,
            "sca_agent": 0.8,
            "iast_agent": 0.7,
            "flaky_test_agent": 0.9,
            "coverage_agent": 0.6,
        }
    
    async def process_security_signal(self, signal: SecuritySignal) -> Optional[PolicyAction]:
        """Process incoming security signal and determine appropriate action."""
        logger.info(f"Processing security signal from {signal.component}: {signal.threat_type}")
        
        self.active_signals.append(signal)
        
        # Apply conflict resolution strategy
        action = await self._resolve_conflicts()
        
        if action:
            self.policy_actions.append(action)
            await self._execute_policy_action(action)
        
        return action
    
    async def process_agent_output(self, agent_name: str, output: Dict[str, Any]) -> Optional[PolicyAction]:
        """
        Process output from an ADK agent and convert to security signal.
        
        Args:
            agent_name: Name of the ADK agent
            output: Agent output dictionary
            
        Returns:
            PolicyAction if action is needed, None otherwise
        """
        # Convert agent output to security signal
        signal = SecuritySignal(
            component=agent_name,
            threat_type=output.get("threat_type", "unknown"),
            confidence=output.get("confidence", 0.5),
            severity=output.get("severity", "medium"),
            metadata=output,
        )
        
        return await self.process_security_signal(signal)
    
    async def _resolve_conflicts(self) -> Optional[PolicyAction]:
        """Resolve conflicts between multiple security signals."""
        if not self.active_signals:
            return None
        
        if self.strategy == ConflictResolutionStrategy.CONSERVATIVE:
            return await self._conservative_resolution()
        elif self.strategy == ConflictResolutionStrategy.MAJORITY_BASED:
            return await self._majority_resolution()
        elif self.strategy == ConflictResolutionStrategy.CONFIDENCE_WEIGHTED:
            return await self._confidence_weighted_resolution()
        
        return None
    
    async def _conservative_resolution(self) -> Optional[PolicyAction]:
        """Apply the strictest security measure."""
        highest_severity = max(
            self.active_signals, 
            key=lambda s: self._severity_score(s.severity)
        )
        
        return PolicyAction(
            action_type="block_deployment",
            target=highest_severity.metadata.get("target", "unknown"),
            parameters={
                "reason": f"Conservative policy: {highest_severity.threat_type}",
                "component": highest_severity.component,
            },
            confidence=highest_severity.confidence
        )
    
    async def _majority_resolution(self) -> Optional[PolicyAction]:
        """Follow majority component decision."""
        threat_votes: Dict[str, int] = {}
        for signal in self.active_signals:
            threat_votes[signal.threat_type] = threat_votes.get(signal.threat_type, 0) + 1
        
        if not threat_votes:
            return None
        
        majority_threat = max(threat_votes, key=lambda k: threat_votes[k])
        majority_signals = [s for s in self.active_signals if s.threat_type == majority_threat]
        avg_confidence = sum(s.confidence for s in majority_signals) / len(majority_signals)
        
        return PolicyAction(
            action_type="review_required",
            target=majority_signals[0].metadata.get("target", "unknown"),
            parameters={
                "threat_type": majority_threat, 
                "votes": threat_votes[majority_threat],
                "components": [s.component for s in majority_signals],
            },
            confidence=avg_confidence
        )
    
    async def _confidence_weighted_resolution(self) -> Optional[PolicyAction]:
        """Use highest confidence signal with component weighting."""
        if not self.active_signals:
            return None
        
        # Calculate weighted confidence scores
        weighted_signals = []
        for signal in self.active_signals:
            component_weight = self.component_weights.get(signal.component, 0.5)
            weighted_confidence = signal.confidence * component_weight
            weighted_signals.append((signal, weighted_confidence))
        
        # Select signal with highest weighted confidence
        best_signal, best_score = max(weighted_signals, key=lambda x: x[1])
        
        # Determine action based on threat type and confidence
        if best_score > 0.85:
            action_type = "auto_remediate"
        elif best_score > 0.7:
            action_type = "block_deployment"
        elif best_score > 0.5:
            action_type = "review_required"
        else:
            action_type = "monitor"
        
        return PolicyAction(
            action_type=action_type,
            target=best_signal.metadata.get("target", "unknown"),
            parameters={
                "threat_type": best_signal.threat_type,
                "weighted_confidence": best_score,
                "original_confidence": best_signal.confidence,
                "component": best_signal.component,
            },
            confidence=best_score
        )
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score."""
        severity_map = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        return severity_map.get(severity.lower(), 0)
    
    async def _execute_policy_action(self, action: PolicyAction):
        """Execute the determined policy action."""
        logger.info(f"Executing policy action: {action.action_type} on {action.target}")
        
        # Actions are logged for now, actual execution depends on integration
        if action.action_type == "auto_remediate":
            logger.info(f"Auto-remediation triggered for {action.target}")
        elif action.action_type == "block_deployment":
            logger.warning(f"Deployment blocked for {action.target}")
        elif action.action_type == "review_required":
            logger.info(f"Human review required for {action.target}")
        elif action.action_type == "monitor":
            logger.info(f"Enhanced monitoring enabled for {action.target}")
    
    def get_active_signals(self) -> List[SecuritySignal]:
        """Get currently active security signals."""
        return self.active_signals.copy()
    
    def clear_signals(self):
        """Clear all active signals."""
        self.active_signals.clear()
        logger.info("Cleared all active security signals")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "active_signals": len(self.active_signals),
            "total_actions": len(self.policy_actions),
            "strategy": self.strategy.value,
            "component_weights": self.component_weights
        }
