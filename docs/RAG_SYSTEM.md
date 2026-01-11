# RAG System

**Retrieval-Augmented Generation for Security Analysis**

The RAG system provides contextual knowledge to the LLM during security analysis, reducing hallucinations and improving accuracy by grounding responses in verified security documentation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          RAG Pipeline                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Challenge Input                                                     │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐     ┌──────────────────────────────────────────┐   │
│  │Query Router │────▶│  Knowledge Bases (ChromaDB)              │   │
│  │(Pillar-aware)│     │  ┌──────────┐ ┌──────────┐ ┌──────────┐ │   │
│  └─────────────┘     │  │vuln_db   │ │examples  │ │android_api│ │   │
│        │             │  └──────────┘ └──────────┘ └──────────┘ │   │
│        │             │  ┌──────────┐                            │   │
│        │             │  │tool_docs │                            │   │
│        ▼             │  └──────────┘                            │   │
│  ┌─────────────┐     └──────────────────────────────────────────┘   │
│  │RAG Context  │◀────────────────────────────────────────────────   │
│  │Builder      │                                                     │
│  └─────────────┘                                                     │
│        │                                                             │
│        ▼                                                             │
│  ┌─────────────┐                                                     │
│  │Augmented    │───▶ LLM (Qwen 32B / MLX)                           │
│  │Prompt       │                                                     │
│  └─────────────┘                                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Knowledge Bases

The RAG system maintains four specialized knowledge bases:

| Knowledge Base | Contents | Source | Purpose |
|----------------|----------|--------|---------|
| `vuln_db` | CWE definitions, OWASP Mobile Top 10 | MITRE, OWASP | Vulnerability classification |
| `examples` | Analysis examples from curriculum | challenges.yaml | Pattern learning |
| `android_api` | API docs, permissions, deprecations | AOSP | API accuracy |
| `tool_docs` | ADB, Frida, jadx commands | Tool documentation | Command accuracy |

### Pillar-Based Routing

The query router weights knowledge bases based on the challenge pillar:

```python
PILLAR_KB_WEIGHTS = {
    "static_analysis":    {"android_api": 0.4, "vuln_db": 0.3, "examples": 0.2, "tool_docs": 0.1},
    "root_cause":         {"vuln_db": 0.5, "examples": 0.3, "android_api": 0.2},
    "taxonomy":           {"vuln_db": 0.6, "examples": 0.3, "android_api": 0.1},
    "methodology":        {"examples": 0.4, "tool_docs": 0.3, "vuln_db": 0.2, "android_api": 0.1},
    "patch_analysis":     {"vuln_db": 0.4, "android_api": 0.3, "examples": 0.2, "tool_docs": 0.1},
    "negative_knowledge": {"examples": 0.4, "android_api": 0.3, "vuln_db": 0.3},
    "pattern_transfer":   {"examples": 0.5, "vuln_db": 0.3, "android_api": 0.2},
}
```

---

## Components

### EmbeddingPipeline

Generates embeddings using `sentence-transformers`:

```python
from dojo.rag import EmbeddingPipeline, EmbeddingConfig

config = EmbeddingConfig(
    model_name="all-MiniLM-L6-v2",  # 384 dimensions, fast
    device="cpu",                    # Keep GPU free for LLM
    normalize_embeddings=True,
)

pipeline = EmbeddingPipeline(config)
embedding = pipeline.embed("SQL injection in ContentProvider")
```

### RAGRetriever

Retrieves relevant documents from knowledge bases:

```python
from dojo.rag import RAGRetriever, RAGConfig

retriever = RAGRetriever(vector_store, config)
results = retriever.retrieve(
    query="WebView JavaScript interface vulnerability",
    pillar="static_analysis",
    top_k=5,
)

for result in results:
    print(f"[{result.source}] {result.score:.3f}: {result.content[:100]}...")
```

### RAGContextBuilder

Builds formatted context with token budgeting:

```python
from dojo.rag import RAGContextBuilder

builder = RAGContextBuilder(retriever, config)
context = builder.build_context(
    query="hardcoded credentials",
    pillar="root_cause",
    max_tokens=2000,
)

print(context.formatted_context)
print(f"Sources: {context.sources}")
print(f"Tokens used: {context.token_count}")
```

### RAGSystem

Unified interface combining all components:

```python
from dojo.rag import RAGSystem, RAGConfig
from pathlib import Path

rag = RAGSystem(
    config=RAGConfig(),
    persist_dir=Path(".rag_data"),
)

# Retrieve documents
results = rag.retrieve("insecure storage", pillar="static_analysis")

# Build context for a challenge
context = rag.build_context_for_challenge(challenge, phase_id="observe")

# Augment a prompt
augmented_prompt = rag.augment_prompt(
    prompt="Analyze this code for vulnerabilities...",
    query="SQL injection ContentProvider",
    pillar="static_analysis",
)
```

---

## Data Loaders

### OWASPMobileLoader

Loads OWASP Mobile Top 10 2024 data:

```python
from dojo.rag.loaders import OWASPMobileLoader

loader = OWASPMobileLoader()

# Get all OWASP categories
categories = loader.get_owasp_ids()  # ['M1', 'M2', ..., 'M10']

# Get CWE mappings
mappings = loader.get_cwe_mappings()
# {'M1': ['CWE-798', 'CWE-312', ...], 'M2': [...], ...}

# Load into knowledge base
count = loader.load_into_kb(vuln_db_kb)
```

### CWELoader

Loads CWE definitions from MITRE:

```python
from dojo.rag.loaders import CWELoader

loader = CWELoader()
loader.download_cwe_data()  # Downloads XML from MITRE
count = loader.load_into_kb(vuln_db_kb)
```

### CurriculumLoader

Extracts examples from challenge ground truth:

```python
from dojo.rag.loaders import CurriculumLoader

loader = CurriculumLoader()
count = loader.load_into_kb(
    examples_kb,
    challenges_dir=Path("dojo/curriculum/v2/pillars"),
)
```

---

## Setup & Population

### One-Time Setup

```bash
# Install dependencies
pip install sentence-transformers chromadb

# Populate knowledge bases
python scripts/populate_rag.py
```

### Population Script

```python
# scripts/populate_rag.py
from pathlib import Path
from dojo.rag import RAGSystem, RAGConfig
from dojo.rag.loaders import OWASPMobileLoader, CurriculumLoader

# Initialize RAG system
rag = RAGSystem(persist_dir=Path(".rag_data"))

# Load OWASP Mobile Top 10
owasp_loader = OWASPMobileLoader()
owasp_loader.load_into_kb(rag.knowledge_bases["vuln_db"])

# Load curriculum examples
curriculum_loader = CurriculumLoader()
curriculum_loader.load_into_kb(rag.knowledge_bases["examples"])

print(rag.get_stats())
```

---

## Integration with PraxisRunner

The RAG system integrates with PraxisRunner to augment prompts during the Praxis Loop:

```python
from dojo.graders.praxis_runner import PraxisRunner

runner = PraxisRunner(
    llm_client=client,
    mcp_executor=executor,
    enable_rag=True,
    rag_persist_dir=Path(".rag_data"),
    rag_max_tokens=2000,
)

# RAG context is automatically injected into prompts
result = runner.run_challenge(challenge)
```

### How It Works

1. **Query Extraction**: Challenge context is converted to a search query
2. **Pillar Routing**: Query routed to relevant knowledge bases based on pillar
3. **Retrieval**: Top-k documents retrieved using semantic similarity
4. **Context Building**: Documents formatted with token budgeting
5. **Prompt Augmentation**: Context injected into LLM prompt
6. **Verification**: LLM response grounded in retrieved knowledge

---

## Configuration

```python
from dojo.rag import RAGConfig, EmbeddingConfig, ChunkingConfig

config = RAGConfig(
    # Embedding settings
    embedding=EmbeddingConfig(
        model_name="all-MiniLM-L6-v2",
        device="cpu",
        max_seq_length=256,
        batch_size=32,
    ),

    # Chunking settings
    chunking=ChunkingConfig(
        chunk_size=512,
        chunk_overlap=50,
    ),

    # Retrieval settings
    top_k=10,
    context_budget_tokens=2000,

    # Persistence
    persist_dir=Path(".rag_data"),
)
```

---

## Testing

```bash
# Run RAG test suite
python scripts/test_rag.py

# Expected output:
# ✓ Core RAG imports successful
# ✓ Knowledge base imports successful
# ✓ Loader imports successful
# ✓ Default config created
# ✓ Pillar weights defined for 7 pillars
# ✓ Single embedding generated (384 dimensions)
# ✓ OWASP Mobile Top 10 data loaded
# ✓ RAG system created
# Total: 6 passed, 0 failed
```

### Manual Retrieval Test

```python
from dojo.rag import RAGSystem
from pathlib import Path

rag = RAGSystem(persist_dir=Path(".rag_data"))

# Test retrieval
results = rag.retrieve("SQL injection", top_k=3)
for r in results:
    print(f"[{r.source}] {r.score:.3f}: {r.content[:80]}...")
```

---

## Directory Structure

```
dojo/rag/
├── __init__.py              # Public API, RAGSystem class
├── config.py                # RAGConfig, EmbeddingConfig, pillar weights
├── embeddings.py            # EmbeddingPipeline, ChromaDBEmbeddingFunction
├── chunking.py              # TextChunker, CodeChunker, DocumentChunker
├── retriever.py             # RAGRetriever, QueryRouter, RetrievalResult
├── context_builder.py       # RAGContextBuilder, RAGContextInjector
├── prompt_augmenter.py      # RAGPromptAugmenter
├── knowledge_bases/
│   ├── __init__.py
│   ├── base.py              # BaseKnowledgeBase
│   ├── android_api.py       # AndroidAPIKnowledgeBase
│   ├── vuln_db.py           # VulnDBKnowledgeBase
│   ├── examples.py          # ExamplesKnowledgeBase
│   └── tool_docs.py         # ToolDocsKnowledgeBase
└── loaders/
    ├── __init__.py
    ├── cwe_loader.py        # CWELoader
    ├── owasp_loader.py      # OWASPMobileLoader
    └── curriculum_loader.py # CurriculumLoader
```

---

## Benefits

1. **Reduced Hallucinations**: LLM responses grounded in verified documentation
2. **Accurate CWE Mapping**: Retrieves correct vulnerability classifications
3. **Context-Aware**: Pillar-based routing provides relevant context
4. **Efficient**: Token budgeting prevents context overflow
5. **Extensible**: Easy to add new knowledge bases and loaders
