"""
Vector Store

Semantic memory using vector embeddings for similarity search.
Supports ChromaDB with multi-collection support for RAG knowledge bases.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class SearchResult:
    """Result from vector similarity search."""
    content: str
    metadata: dict
    score: float
    doc_id: str = ""
    collection: str = ""


@dataclass
class Document:
    """Document to add to vector store."""
    content: str
    metadata: dict = field(default_factory=dict)
    doc_id: Optional[str] = None

    def __post_init__(self):
        if self.doc_id is None:
            self.doc_id = hashlib.md5(self.content.encode()).hexdigest()[:12]


class VectorStore:
    """
    Vector-based semantic memory for storing and retrieving:
    - Past exploitation techniques
    - CVE information
    - Command patterns
    - Session learnings
    - RAG knowledge bases (Android API, CWE, examples, tools)
    """

    def __init__(
        self,
        collection_name: str = "pentest_memory",
        persist_dir: str = ".chromadb",
    ):
        self.default_collection_name = collection_name
        self.persist_dir = Path(persist_dir)
        self._client: Any = None
        self._collections: dict[str, Any] = {}
        self._embedding_function: Any = None

    def _get_client(self):
        """Lazy load ChromaDB client."""
        if self._client is None:
            try:
                import chromadb

                # Use new PersistentClient API (chromadb >= 0.4.0)
                self.persist_dir.mkdir(parents=True, exist_ok=True)
                self._client = chromadb.PersistentClient(
                    path=str(self.persist_dir)
                )
            except ImportError:
                raise ImportError("chromadb required: pip install chromadb")

        return self._client

    def _get_collection(self, collection_name: Optional[str] = None) -> Any:
        """Get or create a collection by name."""
        name = collection_name or self.default_collection_name

        if name not in self._collections:
            client = self._get_client()
            self._collections[name] = client.get_or_create_collection(
                name=name,
                embedding_function=self._embedding_function,
            )

        return self._collections[name]

    def set_embedding_function(self, embedding_function: Any):
        """
        Set custom embedding function for all collections.

        Args:
            embedding_function: ChromaDB-compatible embedding function
        """
        self._embedding_function = embedding_function
        # Clear cached collections so they'll be recreated with new embedding
        self._collections.clear()

    def list_collections(self) -> list[str]:
        """List all collection names."""
        client = self._get_client()
        return [c.name for c in client.list_collections()]

    def get_collection_count(self, collection_name: Optional[str] = None) -> int:
        """Get document count in a collection."""
        collection = self._get_collection(collection_name)
        return collection.count()

    def delete_collection(self, collection_name: str) -> bool:
        """Delete a collection."""
        try:
            client = self._get_client()
            client.delete_collection(collection_name)
            if collection_name in self._collections:
                del self._collections[collection_name]
            return True
        except Exception:
            return False

    def _sanitize_metadata(self, metadata: Optional[dict]) -> dict:
        """
        Sanitize metadata for ChromaDB storage.

        ChromaDB only supports str, int, float, bool values.
        Lists and dicts are converted to JSON strings.
        None values are filtered out (ChromaDB doesn't support None).
        """
        if not metadata:
            return {}

        sanitized = {}
        for key, value in metadata.items():
            if value is None:
                # Skip None values - ChromaDB doesn't support them
                continue
            elif isinstance(value, (list, dict)):
                # Convert to JSON string
                sanitized[key] = json.dumps(value)
            elif isinstance(value, (str, int, float, bool)):
                sanitized[key] = value
            else:
                # Convert other types to string
                sanitized[key] = str(value)
        return sanitized

    def add(
        self,
        content: str,
        metadata: Optional[dict] = None,
        doc_id: Optional[str] = None,
        collection_name: Optional[str] = None,
    ):
        """Add single document to vector store."""
        collection = self._get_collection(collection_name)

        if doc_id is None:
            doc_id = hashlib.md5(content.encode()).hexdigest()[:12]

        collection.add(
            documents=[content],
            metadatas=[self._sanitize_metadata(metadata)],
            ids=[doc_id],
        )

    def add_batch(
        self,
        documents: list[Document],
        collection_name: Optional[str] = None,
        batch_size: int = 100,
    ) -> int:
        """
        Add multiple documents in batches.

        Args:
            documents: List of Document objects
            collection_name: Target collection
            batch_size: Documents per batch (default 100)

        Returns:
            Number of documents added
        """
        collection = self._get_collection(collection_name)
        total_added = 0

        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]

            collection.add(
                documents=[d.content for d in batch],
                metadatas=[self._sanitize_metadata(d.metadata) for d in batch],
                ids=[d.doc_id for d in batch],
            )
            total_added += len(batch)

        return total_added

    def upsert(
        self,
        content: str,
        metadata: Optional[dict] = None,
        doc_id: Optional[str] = None,
        collection_name: Optional[str] = None,
    ):
        """Add or update document in vector store."""
        collection = self._get_collection(collection_name)

        if doc_id is None:
            doc_id = hashlib.md5(content.encode()).hexdigest()[:12]

        collection.upsert(
            documents=[content],
            metadatas=[self._sanitize_metadata(metadata)],
            ids=[doc_id],
        )

    def upsert_batch(
        self,
        documents: list[Document],
        collection_name: Optional[str] = None,
        batch_size: int = 100,
    ) -> int:
        """
        Add or update multiple documents in batches.

        Args:
            documents: List of Document objects
            collection_name: Target collection
            batch_size: Documents per batch (default 100)

        Returns:
            Number of documents upserted
        """
        collection = self._get_collection(collection_name)
        total_upserted = 0

        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]

            collection.upsert(
                documents=[d.content for d in batch],
                metadatas=[self._sanitize_metadata(d.metadata) for d in batch],
                ids=[d.doc_id for d in batch],
            )
            total_upserted += len(batch)

        return total_upserted

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[dict] = None,
        collection_name: Optional[str] = None,
    ) -> list[SearchResult]:
        """Search for similar content in a single collection."""
        collection = self._get_collection(collection_name)
        coll_name = collection_name or self.default_collection_name

        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=filter_metadata,
        )

        search_results = []
        if results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                # ChromaDB returns distances (lower = more similar)
                # Convert to similarity score (higher = more similar)
                distance = results["distances"][0][i] if results.get("distances") else 0.0
                score = 1.0 / (1.0 + distance)  # Convert distance to similarity

                search_results.append(
                    SearchResult(
                        content=doc,
                        metadata=results["metadatas"][0][i] if results.get("metadatas") else {},
                        score=score,
                        doc_id=results["ids"][0][i] if results.get("ids") else "",
                        collection=coll_name,
                    )
                )

        return search_results

    def search_multiple(
        self,
        query: str,
        collection_weights: dict[str, float],
        n_results_per_collection: int = 5,
        filter_metadata: Optional[dict] = None,
    ) -> list[SearchResult]:
        """
        Search across multiple collections with weighted scoring.

        Args:
            query: Search query
            collection_weights: Dict of collection_name -> weight (0.0-1.0)
            n_results_per_collection: Results to fetch from each collection
            filter_metadata: Optional metadata filter

        Returns:
            Merged and re-ranked results from all collections
        """
        all_results = []

        for collection_name, weight in collection_weights.items():
            if weight <= 0:
                continue

            try:
                results = self.search(
                    query=query,
                    n_results=n_results_per_collection,
                    filter_metadata=filter_metadata,
                    collection_name=collection_name,
                )

                # Apply weight to scores
                for result in results:
                    result.score *= weight
                    all_results.append(result)

            except Exception:
                # Collection might not exist yet
                continue

        # Sort by weighted score (descending)
        all_results.sort(key=lambda r: r.score, reverse=True)

        return all_results

    def get_by_id(
        self,
        doc_id: str,
        collection_name: Optional[str] = None,
    ) -> Optional[SearchResult]:
        """Get document by ID."""
        collection = self._get_collection(collection_name)
        coll_name = collection_name or self.default_collection_name

        try:
            result = collection.get(ids=[doc_id])
            if result["documents"] and result["documents"][0]:
                return SearchResult(
                    content=result["documents"][0],
                    metadata=result["metadatas"][0] if result.get("metadatas") else {},
                    score=1.0,
                    doc_id=doc_id,
                    collection=coll_name,
                )
        except Exception:
            pass

        return None

    def delete_by_id(
        self,
        doc_id: str,
        collection_name: Optional[str] = None,
    ) -> bool:
        """Delete document by ID."""
        try:
            collection = self._get_collection(collection_name)
            collection.delete(ids=[doc_id])
            return True
        except Exception:
            return False

    def persist(self):
        """
        Persist vector store to disk.

        Note: With PersistentClient, data is automatically persisted.
        This method is kept for backwards compatibility.
        """
        # PersistentClient auto-persists, no action needed
        pass
