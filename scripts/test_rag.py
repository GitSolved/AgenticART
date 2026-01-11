#!/usr/bin/env python3
"""
RAG System Test Script

Quick verification that the RAG system is working correctly.

Usage:
    python scripts/test_rag.py
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def test_imports():
    """Test that all RAG modules can be imported."""
    print("Testing imports...")

    try:
        from dojo.rag import (
            RAGConfig,
            RAGSystem,
            RAGPromptAugmenter,
            EmbeddingPipeline,
            RAGRetriever,
            RAGContextBuilder,
            create_rag_system,
        )
        print("  ✓ Core RAG imports successful")
    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        return False

    try:
        from dojo.rag.knowledge_bases import (
            BaseKnowledgeBase,
            AndroidAPIKnowledgeBase,
            VulnDBKnowledgeBase,
            ExamplesKnowledgeBase,
            ToolDocsKnowledgeBase,
        )
        print("  ✓ Knowledge base imports successful")
    except ImportError as e:
        print(f"  ✗ Knowledge base import error: {e}")
        return False

    try:
        from dojo.rag.loaders import (
            CWELoader,
            OWASPMobileLoader,
            CurriculumLoader,
        )
        print("  ✓ Loader imports successful")
    except ImportError as e:
        print(f"  ✗ Loader import error: {e}")
        return False

    return True


def test_config():
    """Test RAG configuration."""
    print("\nTesting configuration...")

    from dojo.rag import RAGConfig, PILLAR_KB_WEIGHTS

    config = RAGConfig()
    print(f"  ✓ Default config created")
    print(f"    - Embedding model: {config.embedding.model_name}")
    print(f"    - Context budget: {config.context_budget_tokens} tokens")
    print(f"    - Persist dir: {config.persist_dir}")

    # Check pillar weights
    print(f"  ✓ Pillar weights defined for {len(PILLAR_KB_WEIGHTS)} pillars")

    return True


def test_embedding_pipeline():
    """Test the embedding pipeline."""
    print("\nTesting embedding pipeline...")

    try:
        from dojo.rag import EmbeddingPipeline, EmbeddingConfig

        config = EmbeddingConfig()
        pipeline = EmbeddingPipeline(config)

        # Test single embedding
        text = "SQL injection vulnerability in Android ContentProvider"
        embedding = pipeline.embed(text)

        print(f"  ✓ Single embedding generated")
        print(f"    - Dimensions: {len(embedding)}")
        print(f"    - First 5 values: {embedding[:5]}")

        # Test batch embedding
        texts = [
            "WebView JavaScript interface exploitation",
            "Hardcoded API keys in APK",
            "Insecure SharedPreferences storage",
        ]
        embeddings = pipeline.embed_batch(texts)

        print(f"  ✓ Batch embedding generated ({len(embeddings)} embeddings)")

        return True

    except Exception as e:
        print(f"  ✗ Embedding error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_owasp_loader():
    """Test OWASP loader (no external download required)."""
    print("\nTesting OWASP Mobile Top 10 loader...")

    try:
        from dojo.rag.loaders import OWASPMobileLoader

        loader = OWASPMobileLoader()

        # Check data is present
        owasp_ids = loader.get_owasp_ids()
        print(f"  ✓ OWASP Mobile Top 10 data loaded")
        print(f"    - Categories: {', '.join(owasp_ids)}")

        # Check CWE mappings
        mappings = loader.get_cwe_mappings()
        total_cwes = sum(len(cwes) for cwes in mappings.values())
        print(f"  ✓ CWE mappings: {total_cwes} total CWEs mapped")

        return True

    except Exception as e:
        print(f"  ✗ OWASP loader error: {e}")
        return False


def test_rag_system_creation():
    """Test RAG system creation (without populating)."""
    print("\nTesting RAG system creation...")

    try:
        import tempfile
        from dojo.rag import create_rag_system, RAGConfig

        # Use temp directory for test
        with tempfile.TemporaryDirectory() as tmpdir:
            config = RAGConfig()
            config.persist_dir = Path(tmpdir)

            rag = create_rag_system(config=config)

            print(f"  ✓ RAG system created")

            # Get stats
            stats = rag.get_stats()
            print(f"    - Collections: {stats.get('collections', {})}")
            print(f"    - Total documents: {stats.get('total_documents', 0)}")

        return True

    except Exception as e:
        print(f"  ✗ RAG system creation error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_praxis_rag_integration():
    """Test that PraxisRunner accepts RAG parameters."""
    print("\nTesting Praxis RAG integration...")

    try:
        from dojo.graders.praxis_runner import PraxisRunner, RAG_AVAILABLE

        print(f"  ✓ PraxisRunner imported")
        print(f"    - RAG_AVAILABLE: {RAG_AVAILABLE}")

        # Check that RAG parameters are accepted (don't actually create runner)
        import inspect
        sig = inspect.signature(PraxisRunner.__init__)
        params = list(sig.parameters.keys())

        rag_params = ["enable_rag", "rag_persist_dir", "rag_max_tokens"]
        for param in rag_params:
            if param in params:
                print(f"  ✓ Parameter '{param}' present in PraxisRunner")
            else:
                print(f"  ✗ Parameter '{param}' missing from PraxisRunner")
                return False

        return True

    except Exception as e:
        print(f"  ✗ Praxis integration error: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("RAG System Test Suite")
    print("=" * 60)

    results = []

    results.append(("Imports", test_imports()))
    results.append(("Configuration", test_config()))
    results.append(("Embedding Pipeline", test_embedding_pipeline()))
    results.append(("OWASP Loader", test_owasp_loader()))
    results.append(("RAG System Creation", test_rag_system_creation()))
    results.append(("Praxis Integration", test_praxis_rag_integration()))

    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\nTotal: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
