"""
Vector Store - ChromaDB integration for semantic search.

Used for:
- Vulnerability pattern matching
- Flaky test log similarity search
- Remediation example retrieval
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Result from a vector search."""
    id: str
    content: str
    metadata: Dict[str, Any]
    score: float


class VectorStore:
    """
    Vector database interface for semantic search.
    
    Collections:
    - vulnerability_patterns: Known vulnerability signatures
    - flaky_test_logs: Historical flaky test patterns
    - remediation_examples: Successful fix examples
    """
    
    COLLECTION_VULNERABILITIES = "vulnerability_patterns"
    COLLECTION_FLAKY_LOGS = "flaky_test_logs"
    COLLECTION_REMEDIATIONS = "remediation_examples"
    
    def __init__(self, persist_directory: Optional[str] = None):
        """
        Initialize vector store.
        
        Args:
            persist_directory: Directory for persistent storage (None for in-memory)
        """
        self.persist_directory = persist_directory
        self._client = None
        self._collections: Dict[str, Any] = {}
        
    def _get_client(self):
        """Lazy initialization of ChromaDB client."""
        if self._client is None:
            try:
                import chromadb
                
                if self.persist_directory:
                    # Use persistent client for production
                    self._client = chromadb.PersistentClient(
                        path=self.persist_directory
                    )
                else:
                    # Use ephemeral (in-memory) client for testing
                    self._client = chromadb.EphemeralClient()
                    
                logger.info("ChromaDB client initialized")
            except Exception as e:
                logger.warning(f"ChromaDB initialization failed ({e}), using mock implementation")
                self._client = MockChromaClient()
                
        return self._client
    
    def _get_collection(self, name: str):
        """Get or create a collection."""
        if name not in self._collections:
            client = self._get_client()
            self._collections[name] = client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )
        return self._collections[name]
    
    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ):
        """
        Add documents to a collection.
        
        Args:
            collection_name: Name of the collection
            documents: List of document texts
            metadatas: Optional list of metadata dicts
            ids: Optional list of document IDs
        """
        collection = self._get_collection(collection_name)
        
        if ids is None:
            import uuid
            ids = [str(uuid.uuid4()) for _ in documents]
        
        if metadatas is None:
            metadatas = [{} for _ in documents]
        
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        logger.info(f"Added {len(documents)} documents to {collection_name}")
    
    def search(
        self,
        collection_name: str,
        query: str,
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """
        Search for similar documents.
        
        Args:
            collection_name: Name of the collection
            query: Search query text
            n_results: Number of results to return
            where: Optional filter conditions
            
        Returns:
            List of SearchResult objects
        """
        collection = self._get_collection(collection_name)
        
        kwargs = {
            "query_texts": [query],
            "n_results": n_results,
        }
        if where:
            kwargs["where"] = where
        
        results = collection.query(**kwargs)
        
        search_results = []
        if results and results.get("ids"):
            for i, doc_id in enumerate(results["ids"][0]):
                search_results.append(SearchResult(
                    id=doc_id,
                    content=results["documents"][0][i] if results.get("documents") else "",
                    metadata=results["metadatas"][0][i] if results.get("metadatas") else {},
                    score=1 - results["distances"][0][i] if results.get("distances") else 0.0
                ))
        
        return search_results
    
    def add_vulnerability_pattern(
        self,
        pattern_id: str,
        description: str,
        vulnerability_type: str,
        severity: str,
        cwe_id: Optional[str] = None
    ):
        """Add a vulnerability pattern for matching."""
        self.add_documents(
            collection_name=self.COLLECTION_VULNERABILITIES,
            documents=[description],
            metadatas=[{
                "type": vulnerability_type,
                "severity": severity,
                "cwe_id": cwe_id or "",
            }],
            ids=[pattern_id]
        )
    
    def search_vulnerability_patterns(
        self,
        description: str,
        severity_filter: Optional[str] = None,
        n_results: int = 5
    ) -> List[SearchResult]:
        """Search for similar vulnerability patterns."""
        where = {"severity": severity_filter} if severity_filter else None
        return self.search(
            collection_name=self.COLLECTION_VULNERABILITIES,
            query=description,
            n_results=n_results,
            where=where
        )
    
    def add_flaky_log_pattern(
        self,
        log_id: str,
        log_content: str,
        test_name: str,
        is_flaky: bool,
        root_cause: Optional[str] = None
    ):
        """Add a flaky test log pattern."""
        self.add_documents(
            collection_name=self.COLLECTION_FLAKY_LOGS,
            documents=[log_content],
            metadatas=[{
                "test_name": test_name,
                "is_flaky": is_flaky,
                "root_cause": root_cause or "",
            }],
            ids=[log_id]
        )
    
    def search_similar_failures(
        self,
        log_content: str,
        n_results: int = 5
    ) -> List[SearchResult]:
        """Search for similar test failure logs."""
        return self.search(
            collection_name=self.COLLECTION_FLAKY_LOGS,
            query=log_content,
            n_results=n_results
        )
    
    def add_remediation_example(
        self,
        example_id: str,
        vulnerability_description: str,
        fix_description: str,
        code_before: str,
        code_after: str
    ):
        """Add a remediation example for reference."""
        combined = f"{vulnerability_description}\n\nFix: {fix_description}"
        self.add_documents(
            collection_name=self.COLLECTION_REMEDIATIONS,
            documents=[combined],
            metadatas=[{
                "code_before": code_before,
                "code_after": code_after,
            }],
            ids=[example_id]
        )
    
    def search_remediations(
        self,
        vulnerability_description: str,
        n_results: int = 3
    ) -> List[SearchResult]:
        """Search for relevant remediation examples."""
        return self.search(
            collection_name=self.COLLECTION_REMEDIATIONS,
            query=vulnerability_description,
            n_results=n_results
        )


class MockChromaClient:
    """Mock ChromaDB client for when chromadb is not installed."""
    
    def __init__(self):
        self._collections: Dict[str, MockCollection] = {}
    
    def get_or_create_collection(self, name: str, **kwargs):
        if name not in self._collections:
            self._collections[name] = MockCollection(name)
        return self._collections[name]


class MockCollection:
    """Mock collection for testing without ChromaDB."""
    
    def __init__(self, name: str):
        self.name = name
        self._documents: Dict[str, Dict] = {}
    
    def add(self, documents: List[str], metadatas: List[Dict], ids: List[str]):
        for i, doc_id in enumerate(ids):
            self._documents[doc_id] = {
                "document": documents[i],
                "metadata": metadatas[i],
            }
    
    def query(self, query_texts: List[str], n_results: int, **kwargs):
        # Simple mock: return all documents
        all_ids = list(self._documents.keys())[:n_results]
        return {
            "ids": [all_ids],
            "documents": [[self._documents[id]["document"] for id in all_ids]],
            "metadatas": [[self._documents[id]["metadata"] for id in all_ids]],
            "distances": [[0.5] * len(all_ids)],
        }
