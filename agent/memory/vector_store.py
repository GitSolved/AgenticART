"""
Vector Store

Semantic memory using vector embeddings for similarity search.
Supports ChromaDB (default), with extensibility for pgvector/FAISS.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SearchResult:
    """Result from vector similarity search."""
    content: str
    metadata: dict
    score: float


class VectorStore:
    """
    Vector-based semantic memory for storing and retrieving:
    - Past exploitation techniques
    - CVE information
    - Command patterns
    - Session learnings
    """

    def __init__(
        self,
        collection_name: str = "pentest_memory",
        persist_dir: str = ".chromadb",
    ):
        self.collection_name = collection_name
        self.persist_dir = persist_dir
        self._client = None
        self._collection = None

    def _get_client(self):
        """Lazy load ChromaDB client."""
        if self._client is None:
            try:
                import chromadb
                from chromadb.config import Settings

                self._client = chromadb.Client(
                    Settings(
                        chroma_db_impl="duckdb+parquet",
                        persist_directory=self.persist_dir,
                    )
                )
                self._collection = self._client.get_or_create_collection(
                    name=self.collection_name
                )
            except ImportError:
                raise ImportError("chromadb required: pip install chromadb")

        return self._client

    def add(
        self,
        content: str,
        metadata: Optional[dict] = None,
        doc_id: Optional[str] = None,
    ):
        """Add content to vector store."""
        self._get_client()

        import hashlib
        if doc_id is None:
            doc_id = hashlib.md5(content.encode()).hexdigest()[:12]

        self._collection.add(
            documents=[content],
            metadatas=[metadata or {}],
            ids=[doc_id],
        )

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[dict] = None,
    ) -> list[SearchResult]:
        """Search for similar content."""
        self._get_client()

        results = self._collection.query(
            query_texts=[query],
            n_results=n_results,
            where=filter_metadata,
        )

        search_results = []
        if results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                search_results.append(
                    SearchResult(
                        content=doc,
                        metadata=results["metadatas"][0][i] if results["metadatas"] else {},
                        score=results["distances"][0][i] if results["distances"] else 0.0,
                    )
                )

        return search_results

    def persist(self):
        """Persist vector store to disk."""
        if self._client:
            self._client.persist()
