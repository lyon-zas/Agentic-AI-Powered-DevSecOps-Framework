"""
Security Message Bus - Event-driven communication between agents.

Provides pub/sub messaging for security events and agent coordination.
"""

import asyncio
import logging
import time
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from queue import Queue
import threading

logger = logging.getLogger(__name__)


@dataclass
class SecurityMessage:
    """A message in the security message bus."""
    topic: str
    source: str
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    correlation_id: Optional[str] = None


class SecurityMessageBus:
    """
    Event-driven message bus for security agent communication.
    
    Supports:
    - Pub/sub messaging between agents
    - Async and sync message handling
    - Message enrichment with context
    - Topic-based routing
    """
    
    # Standard topics
    TOPIC_VULNERABILITY = "security.vulnerability"
    TOPIC_TEST_IMPACT = "test.impact"
    TOPIC_FLAKY_TEST = "test.flaky"
    TOPIC_COVERAGE = "test.coverage"
    TOPIC_DEPLOYMENT = "deployment.event"
    TOPIC_REMEDIATION = "security.remediation"
    
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.async_subscribers: Dict[str, List[Callable]] = {}
        self.message_queue: Queue = Queue()
        self.message_history: List[SecurityMessage] = []
        self._worker_running = False
        self._context: Dict[str, Any] = {}
        
    def start(self):
        """Start the message processing worker thread."""
        if not self._worker_running:
            self._worker_running = True
            thread = threading.Thread(target=self._worker, daemon=True)
            thread.start()
            logger.info("Message bus worker started")
    
    def stop(self):
        """Stop the message processing worker."""
        self._worker_running = False
        logger.info("Message bus worker stopped")
    
    def _worker(self):
        """Background worker that processes messages from the queue."""
        while self._worker_running:
            try:
                if not self.message_queue.empty():
                    message = self.message_queue.get(timeout=0.1)
                    self._process_message(message)
                    self.message_queue.task_done()
                else:
                    time.sleep(0.01)
            except Exception as e:
                logger.error(f"Error in message bus worker: {e}")
    
    def _process_message(self, message: SecurityMessage):
        """Process a message by notifying all subscribers."""
        topic = message.topic
        
        # Store in history
        self.message_history.append(message)
        if len(self.message_history) > 1000:
            self.message_history = self.message_history[-500:]
        
        # Notify sync subscribers
        if topic in self.subscribers:
            for callback in self.subscribers[topic]:
                try:
                    callback(message)
                except Exception as e:
                    logger.error(f"Error in subscriber callback: {e}")
        
        # Notify wildcard subscribers
        if "*" in self.subscribers:
            for callback in self.subscribers["*"]:
                try:
                    callback(message)
                except Exception as e:
                    logger.error(f"Error in wildcard subscriber callback: {e}")
    
    def publish(self, topic: str, source: str, payload: Dict[str, Any], correlation_id: Optional[str] = None):
        """
        Publish a message to a topic.
        
        Args:
            topic: Message topic (use class constants)
            source: Source agent/component name
            payload: Message data
            correlation_id: Optional ID for tracking related messages
        """
        message = SecurityMessage(
            topic=topic,
            source=source,
            payload=self._enrich_payload(payload),
            correlation_id=correlation_id,
        )
        
        self.message_queue.put(message)
        logger.debug(f"Published message to {topic} from {source}")
    
    async def publish_async(self, topic: str, source: str, payload: Dict[str, Any], correlation_id: Optional[str] = None):
        """Async version of publish."""
        message = SecurityMessage(
            topic=topic,
            source=source,
            payload=self._enrich_payload(payload),
            correlation_id=correlation_id,
        )
        
        # Store in history
        self.message_history.append(message)
        
        # Notify async subscribers
        if topic in self.async_subscribers:
            tasks = [callback(message) for callback in self.async_subscribers[topic]]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.debug(f"Published async message to {topic} from {source}")
    
    def subscribe(self, topic: str, callback: Callable[[SecurityMessage], None]):
        """
        Subscribe to a topic with a sync callback.
        
        Args:
            topic: Topic to subscribe to (use "*" for all topics)
            callback: Function to call when message received
        """
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)
        logger.debug(f"Subscribed to {topic}")
    
    def subscribe_async(self, topic: str, callback: Callable[[SecurityMessage], Any]):
        """
        Subscribe to a topic with an async callback.
        
        Args:
            topic: Topic to subscribe to
            callback: Async function to call when message received
        """
        if topic not in self.async_subscribers:
            self.async_subscribers[topic] = []
        self.async_subscribers[topic].append(callback)
        logger.debug(f"Async subscribed to {topic}")
    
    def unsubscribe(self, topic: str, callback: Callable):
        """Unsubscribe a callback from a topic."""
        if topic in self.subscribers and callback in self.subscribers[topic]:
            self.subscribers[topic].remove(callback)
        if topic in self.async_subscribers and callback in self.async_subscribers[topic]:
            self.async_subscribers[topic].remove(callback)
    
    def _enrich_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich message payload with context."""
        enriched = payload.copy()
        enriched["_enriched_at"] = time.time()
        enriched["_context"] = self._context.copy()
        return enriched
    
    def set_context(self, key: str, value: Any):
        """Set a context value that will be included in all messages."""
        self._context[key] = value
    
    def clear_context(self):
        """Clear all context values."""
        self._context.clear()
    
    def get_messages_by_topic(self, topic: str, limit: int = 100) -> List[SecurityMessage]:
        """Get recent messages for a topic."""
        return [m for m in self.message_history if m.topic == topic][-limit:]
    
    def get_messages_by_correlation(self, correlation_id: str) -> List[SecurityMessage]:
        """Get all messages with a specific correlation ID."""
        return [m for m in self.message_history if m.correlation_id == correlation_id]
