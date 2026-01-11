#!/usr/bin/env python3
"""
RAG Knowledge Base Population Script

One-shot script to populate all RAG knowledge bases with data.

Usage:
    python scripts/populate_rag.py [--all] [--cwe] [--owasp] [--curriculum] [--synthetic]

Options:
    --all         Populate all knowledge bases
    --cwe         Populate CWE database (downloads from MITRE)
    --owasp       Populate OWASP Mobile Top 10
    --curriculum  Populate from curriculum challenges
    --synthetic   Add synthetic examples for bootstrapping
    --force       Force re-download of external data
    --stats       Show statistics after population
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def create_knowledge_bases(persist_dir: Path):
    """Create knowledge base instances."""
    from agent.memory.vector_store import VectorStore
    from dojo.rag import EmbeddingPipeline, RAGConfig
    from dojo.rag.embeddings import ChromaDBEmbeddingFunction
    from dojo.rag.knowledge_bases import (
        AndroidAPIKnowledgeBase,
        ExamplesKnowledgeBase,
        ToolDocsKnowledgeBase,
        VulnDBKnowledgeBase,
    )

    # Initialize vector store
    vector_store = VectorStore(persist_dir=str(persist_dir))

    # Set up embedding function
    config = RAGConfig()
    embeddings = EmbeddingPipeline(config.embedding)
    embedding_fn = ChromaDBEmbeddingFunction(embeddings)
    vector_store.set_embedding_function(embedding_fn)

    # Create knowledge bases
    return {
        "android_api": AndroidAPIKnowledgeBase(vector_store),
        "vuln_db": VulnDBKnowledgeBase(vector_store),
        "examples": ExamplesKnowledgeBase(vector_store),
        "tool_docs": ToolDocsKnowledgeBase(vector_store),
    }, vector_store


def populate_cwe(vuln_kb, force: bool = False) -> int:
    """Populate CWE database."""
    from dojo.rag.loaders import CWELoader

    print("\n📚 Loading CWE database...")
    loader = CWELoader()

    try:
        count = loader.load_to_knowledge_base(vuln_kb, android_only=True)
        print(f"   ✓ Loaded {count} Android-relevant CWE entries")
        return count
    except Exception as e:
        print(f"   ✗ Failed to load CWE database: {e}")
        return 0


def populate_owasp(vuln_kb) -> int:
    """Populate OWASP Mobile Top 10."""
    from dojo.rag.loaders import OWASPMobileLoader

    print("\n📱 Loading OWASP Mobile Top 10 2024...")
    loader = OWASPMobileLoader()

    count = loader.load_to_knowledge_base(vuln_kb)
    print(f"   ✓ Loaded {count} OWASP Mobile entries")
    return count


def populate_curriculum(examples_kb, curriculum_dir: Path = None) -> int:
    """Populate from curriculum challenges."""
    from dojo.rag.loaders import CurriculumLoader

    print("\n🎓 Loading curriculum examples...")

    # Find curriculum directory
    if not curriculum_dir:
        possible_dirs = [
            project_root / "curriculum",
            project_root / "dojo" / "curriculum",
            project_root / "challenges",
        ]
        for d in possible_dirs:
            if d.exists():
                curriculum_dir = d
                break

    loader = CurriculumLoader(curriculum_dir)
    count = loader.load_to_knowledge_base(examples_kb)

    if count > 0:
        print(f"   ✓ Loaded {count} curriculum examples")
    else:
        print("   ⚠ No curriculum files found")

    return count


def populate_synthetic(examples_kb) -> int:
    """Populate synthetic examples for bootstrapping."""
    from dojo.rag.loaders import CurriculumLoader

    print("\n🔧 Creating synthetic examples...")
    loader = CurriculumLoader()

    count = loader.create_synthetic_examples(examples_kb)
    print(f"   ✓ Created {count} synthetic examples")
    return count


def populate_android_api(android_api_kb) -> int:
    """Populate Android API knowledge base with security-relevant APIs."""
    print("\n📱 Loading Android API documentation...")

    # Security-relevant Android APIs
    ANDROID_APIS = [
        {
            "signature": "WebView.setJavaScriptEnabled(boolean)",
            "package": "android.webkit",
            "class": "WebView",
            "method": "setJavaScriptEnabled",
            "description": "Enables or disables JavaScript execution in WebView.",
            "min_sdk": 1,
            "security_note": "Enabling JavaScript in WebView loading untrusted URLs can lead to XSS attacks.",
        },
        {
            "signature": "WebView.addJavascriptInterface(Object, String)",
            "package": "android.webkit",
            "class": "WebView",
            "method": "addJavascriptInterface",
            "description": "Injects Java object into WebView accessible from JavaScript.",
            "min_sdk": 1,
            "security_note": "CRITICAL: On API < 17, ALL public methods exposed to JS. Always use @JavascriptInterface.",
        },
        {
            "signature": "ContentProvider.query(Uri, String[], String, String[], String)",
            "package": "android.content",
            "class": "ContentProvider",
            "method": "query",
            "description": "Retrieves data from content provider using SQL-like query.",
            "min_sdk": 1,
            "security_note": "SQL injection if selection param built with user input. Use parameterized queries.",
        },
        {
            "signature": "Context.getSharedPreferences(String, int)",
            "package": "android.content",
            "class": "Context",
            "method": "getSharedPreferences",
            "description": "Retrieves SharedPreferences for key-value storage.",
            "min_sdk": 1,
            "security_note": "MODE_WORLD_READABLE/WRITEABLE deprecated. Use MODE_PRIVATE. Encrypt sensitive data.",
        },
        {
            "signature": "SQLiteDatabase.rawQuery(String, String[])",
            "package": "android.database.sqlite",
            "class": "SQLiteDatabase",
            "method": "rawQuery",
            "description": "Runs SQL query and returns Cursor.",
            "min_sdk": 1,
            "security_note": "SQL injection if query built with user input. Use selectionArgs parameter.",
        },
        {
            "signature": "Log.d(String, String)",
            "package": "android.util",
            "class": "Log",
            "method": "d",
            "description": "Logs debug message visible in logcat.",
            "min_sdk": 1,
            "security_note": "Logging sensitive data is a risk. Remove sensitive logs in production.",
        },
        {
            "signature": "Intent.getStringExtra(String)",
            "package": "android.content",
            "class": "Intent",
            "method": "getStringExtra",
            "description": "Retrieves extended string data from Intent.",
            "min_sdk": 1,
            "security_note": "Intent extras from external apps are untrusted. Validate before use.",
        },
        {
            "signature": "Cipher.getInstance(String)",
            "package": "javax.crypto",
            "class": "Cipher",
            "method": "getInstance",
            "description": "Returns Cipher for specified transformation.",
            "min_sdk": 1,
            "security_note": "Avoid DES, 3DES, ECB mode. Use AES/GCM/NoPadding with random IV.",
        },
        {
            "signature": "SecretKeySpec(byte[], String)",
            "package": "javax.crypto.spec",
            "class": "SecretKeySpec",
            "method": "<init>",
            "description": "Constructs secret key from byte array.",
            "min_sdk": 1,
            "security_note": "Hardcoded keys extractable from APK. Use Android Keystore instead.",
        },
        {
            "signature": "X509TrustManager.checkServerTrusted",
            "package": "javax.net.ssl",
            "class": "X509TrustManager",
            "method": "checkServerTrusted",
            "description": "Validates server certificate chain.",
            "min_sdk": 1,
            "security_note": "Empty implementation disables SSL validation enabling MITM attacks.",
        },
        {
            "signature": "Runtime.exec(String)",
            "package": "java.lang",
            "class": "Runtime",
            "method": "exec",
            "description": "Executes command in separate process.",
            "min_sdk": 1,
            "security_note": "Command injection if user input in command. Use ProcessBuilder instead.",
        },
        {
            "signature": "File(String)",
            "package": "java.io",
            "class": "File",
            "method": "<init>",
            "description": "Creates File from pathname string.",
            "min_sdk": 1,
            "security_note": "Path traversal if pathname has '../'. Canonicalize and validate paths.",
        },
    ]

    count = 0
    for api in ANDROID_APIS:
        android_api_kb.add_api_entry(
            signature=api["signature"],
            package=api["package"],
            class_name=api["class"],
            method_name=api.get("method"),
            description=api["description"],
            min_sdk=api.get("min_sdk", 1),
            deprecated_sdk=api.get("deprecated_sdk"),
            permissions=api.get("permissions", []),
            security_note=api.get("security_note"),
        )
        count += 1

    print(f"   ✓ Loaded {count} Android API entries")
    return count


def populate_tool_docs(tool_docs_kb) -> int:
    """Populate tool documentation knowledge base."""
    print("\n🔧 Loading tool documentation...")

    count = 0

    # ADB Commands
    ADB_COMMANDS = [
        ("adb devices", "adb devices [-l]", "Lists connected Android devices", "device",
         ["adb devices", "adb devices -l"], "Verify device serial matches expected device."),
        ("adb shell", "adb shell [command]", "Opens shell or runs command on device", "shell",
         ["adb shell", "adb shell id", "adb shell pm list packages"], "Use 'su' for root on rooted devices."),
        ("adb pull", "adb pull <remote> [local]", "Copies file from device to local", "file",
         ["adb pull /data/data/com.app/shared_prefs/prefs.xml ./"], "Access to /data/data/ requires root."),
        ("adb push", "adb push <local> <remote>", "Copies file from local to device", "file",
         ["adb push frida-server /data/local/tmp/"], "Deploy Frida server and test payloads."),
        ("adb install", "adb install [-r] [-t] [-g] <apk>", "Installs APK on device", "package",
         ["adb install app.apk", "adb install -r -t modified.apk"], "Use -t for repackaged APKs."),
        ("adb logcat", "adb logcat [filter-spec]", "Prints device log output", "debug",
         ["adb logcat", "adb logcat | grep -i password"], "Search for password, token, key, secret."),
        ("pm list packages", "adb shell pm list packages [-f] [-3]", "Lists installed packages", "package",
         ["adb shell pm list packages -3", "adb shell pm list packages -f"], "Identify target package name."),
        ("pm path", "adb shell pm path <package>", "Prints APK path", "package",
         ["adb shell pm path com.target.app"], "Use with 'adb pull' to extract APK."),
        ("am start", "adb shell am start [-n component] [-a action] [-d data]", "Starts Activity", "activity",
         ["adb shell am start -n com.app/.MainActivity"], "Test exported activities, bypass auth."),
        ("content query", "adb shell content query --uri <uri>", "Queries content provider", "content",
         ["adb shell content query --uri content://com.app/users"], "Test for data leakage and SQLi."),
        ("run-as", "adb shell run-as <package> [cmd]", "Runs command as app user", "debug",
         ["adb shell run-as com.app cat shared_prefs/prefs.xml"], "Only works if debuggable=true."),
        ("dumpsys", "adb shell dumpsys [service]", "Dumps system service info", "system",
         ["adb shell dumpsys package com.app"], "Shows permissions, components, signatures."),
    ]

    for cmd, syntax, desc, cat, examples, notes in ADB_COMMANDS:
        tool_docs_kb.add_command("adb", cmd, syntax, desc, category=cat, examples=examples, security_notes=notes)
        count += 1

    # Frida Scripts
    tool_docs_kb.add_frida_script_example(
        script_id="ssl_bypass",
        title="SSL Pinning Bypass",
        description="Bypasses TrustManager SSL pinning to intercept HTTPS traffic.",
        use_case="Intercept HTTPS from apps with certificate pinning",
        api_hooks=["javax.net.ssl.X509TrustManager"],
        script="""Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] SSL check bypassed");
    };
});""",
    )
    count += 1

    tool_docs_kb.add_frida_script_example(
        script_id="crypto_hook",
        title="Cryptographic Operations Logger",
        description="Logs encryption keys and data being encrypted/decrypted.",
        use_case="Discover encryption keys and observe crypto operations",
        api_hooks=["javax.crypto.Cipher", "javax.crypto.spec.SecretKeySpec"],
        script="""Java.perform(function() {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log("[KEY] " + algo + ": " + bytes2hex(key));
        return this.$init(key, algo);
    };
});""",
    )
    count += 1

    tool_docs_kb.add_frida_script_example(
        script_id="root_bypass",
        title="Root Detection Bypass",
        description="Bypasses root detection by hiding su binary and modifying Build properties.",
        use_case="Run app on rooted device when root detection blocks it",
        api_hooks=["java.io.File", "android.os.Build"],
        script="""Java.perform(function() {
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1) {
            return false;
        }
        return this.exists();
    };
});""",
    )
    count += 1

    # jadx commands
    tool_docs_kb.add_command(
        "jadx", "jadx", "jadx [options] <input.apk> [-d <output>]",
        "Decompiles APK/DEX to Java source code",
        category="decompile",
        examples=["jadx app.apk -d ./output", "jadx --deobf app.apk"],
        security_notes="Use --deobf for obfuscated code, --show-bad-code for failures.",
    )
    count += 1

    tool_docs_kb.add_command(
        "jadx", "jadx-gui", "jadx-gui [input.apk]",
        "Interactive GUI for code browsing and searching",
        category="gui",
        examples=["jadx-gui app.apk"],
        security_notes="GUI provides search and cross-references for finding secrets.",
    )
    count += 1

    # Workflows
    tool_docs_kb.add_adb_workflow(
        workflow_id="extract_apk",
        title="Extract APK from Device",
        description="Extract installed APK for decompilation and analysis.",
        steps=[
            {"description": "Find package name", "command": "adb shell pm list packages | grep target"},
            {"description": "Get APK path", "command": "adb shell pm path com.target.app"},
            {"description": "Pull APK", "command": "adb pull /data/app/.../base.apk ./target.apk"},
        ],
        prerequisites=["ADB connected", "USB debugging enabled"],
    )
    count += 1

    tool_docs_kb.add_adb_workflow(
        workflow_id="frida_setup",
        title="Setup Frida Server",
        description="Deploy and start Frida for dynamic instrumentation.",
        steps=[
            {"description": "Push frida-server", "command": "adb push frida-server /data/local/tmp/"},
            {"description": "Make executable", "command": "adb shell chmod 755 /data/local/tmp/frida-server"},
            {"description": "Start as root", "command": "adb shell su -c '/data/local/tmp/frida-server &'"},
            {"description": "Verify", "command": "frida-ps -U"},
        ],
        prerequisites=["Root access", "Frida installed locally"],
    )
    count += 1

    print(f"   ✓ Loaded {count} tool documentation entries")
    return count


def show_stats(knowledge_bases: dict, vector_store) -> None:
    """Display statistics about knowledge bases."""
    print("\n" + "=" * 50)
    print("📊 RAG Knowledge Base Statistics")
    print("=" * 50)

    total = 0
    for name, kb in knowledge_bases.items():
        count = kb.count()
        total += count
        print(f"   {kb.DISPLAY_NAME}: {count} documents")

    print("-" * 50)
    print(f"   Total: {total} documents")

    # Show collections
    collections = vector_store.list_collections()
    print(f"\n   Collections: {', '.join(collections)}")


def main():
    parser = argparse.ArgumentParser(
        description="Populate RAG knowledge bases for AgenticART"
    )
    parser.add_argument("--all", action="store_true", help="Populate all knowledge bases")
    parser.add_argument("--cwe", action="store_true", help="Populate CWE database")
    parser.add_argument("--owasp", action="store_true", help="Populate OWASP Mobile Top 10")
    parser.add_argument("--curriculum", action="store_true", help="Populate from curriculum")
    parser.add_argument("--synthetic", action="store_true", help="Add synthetic examples")
    parser.add_argument("--android-api", action="store_true", help="Populate Android API docs")
    parser.add_argument("--tool-docs", action="store_true", help="Populate tool documentation (ADB, Frida, jadx)")
    parser.add_argument("--force", action="store_true", help="Force re-download")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument(
        "--persist-dir",
        type=Path,
        default=project_root / ".rag_data",
        help="Directory for vector store persistence",
    )

    args = parser.parse_args()

    # If no specific options, default to --all
    has_specific = any([
        args.all, args.cwe, args.owasp, args.curriculum,
        args.synthetic, args.android_api, args.tool_docs, args.stats
    ])
    if not has_specific:
        args.all = True

    print("🚀 AgenticART RAG Knowledge Base Population")
    print(f"   Persist directory: {args.persist_dir}")

    # Create knowledge bases
    knowledge_bases, vector_store = create_knowledge_bases(args.persist_dir)

    total_loaded = 0

    # Populate based on options
    if args.all or args.owasp:
        total_loaded += populate_owasp(knowledge_bases["vuln_db"])

    if args.all or args.cwe:
        total_loaded += populate_cwe(knowledge_bases["vuln_db"], force=args.force)

    if args.all or args.curriculum:
        total_loaded += populate_curriculum(knowledge_bases["examples"])

    if args.all or args.synthetic:
        total_loaded += populate_synthetic(knowledge_bases["examples"])

    if args.all or args.android_api:
        total_loaded += populate_android_api(knowledge_bases["android_api"])

    if args.all or args.tool_docs:
        total_loaded += populate_tool_docs(knowledge_bases["tool_docs"])

    # Always show stats after population
    if args.stats or total_loaded > 0:
        show_stats(knowledge_bases, vector_store)

    print(f"\n✅ Done! Loaded {total_loaded} total documents.")


if __name__ == "__main__":
    main()
