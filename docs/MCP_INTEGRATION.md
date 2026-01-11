# MCP Integration

**Model Context Protocol for Android Security Tools**

The MCP (Model Context Protocol) integration provides a standardized interface for the Praxis Loop to execute verification tasks against Android security analysis tools.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Praxis Verification Layer                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PraxisRunner                                                        │
│       │                                                              │
│       ▼                                                              │
│  ┌─────────────┐                                                     │
│  │MCPExecutor  │──────┬──────────┬──────────┬──────────┐            │
│  └─────────────┘      │          │          │          │            │
│                       ▼          ▼          ▼          ▼            │
│                 ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│                 │  JADX   │ │Apktool  │ │  ADB    │ │ Frida   │    │
│                 │ Server  │ │ Server  │ │ Server  │ │ Server  │    │
│                 └─────────┘ └─────────┘ └─────────┘ └─────────┘    │
│                       │          │          │          │            │
│                       ▼          ▼          ▼          ▼            │
│                 ┌─────────────────────────────────────────────┐     │
│                 │              Tool Results                    │     │
│                 │  (Binary ground truth for calibration)       │     │
│                 └─────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## MCP Servers

### Available Servers

| Server | Tools | Purpose |
|--------|-------|---------|
| `jadx` | `decompile`, `search_code`, `get_class`, `list_classes`, `get_method`, `find_security_patterns` | Java decompilation and code search |
| `apktool` | `decode`, `get_manifest`, `get_smali`, `search_smali`, `get_strings`, `find_security_issues` | APK decoding and resource extraction |
| `adb` | `adb_shell`, `get_package_info` | Device interaction |
| `frida` | `frida_attach`, `frida_spawn`, `frida_script` | Dynamic instrumentation (planned) |

### JADX Server

Provides Java decompilation and code analysis:

```python
# Tools available
tools = [
    "decompile",           # Decompile APK to Java
    "search_code",         # Search for patterns in decompiled code
    "get_class",           # Get specific class source
    "list_classes",        # List all classes in package
    "get_method",          # Get specific method source
    "find_security_patterns",  # Find security-relevant patterns
]
```

**Usage:**

```bash
# Start JADX server
python -m dojo.mcp.servers.jadx_server
```

### Apktool Server

Provides APK decoding and resource extraction:

```python
# Tools available
tools = [
    "decode",              # Decode APK to smali/resources
    "get_manifest",        # Extract AndroidManifest.xml
    "get_smali",           # Get smali code for class
    "search_smali",        # Search smali bytecode
    "get_strings",         # Extract strings.xml
    "list_resources",      # List all resources
    "get_resource",        # Get specific resource file
    "build",               # Rebuild APK from decoded
    "find_security_issues", # Find security issues in manifest
]
```

**Usage:**

```bash
# Start Apktool server
python -m dojo.mcp.servers.apktool_server
```

---

## MCPExecutor

The `MCPExecutor` bridges PraxisRunner to MCP servers:

```python
from dojo.mcp import MCPExecutor, ToolResult

# Initialize executor
executor = MCPExecutor()
await executor.initialize()

# Execute a tool
result: ToolResult = await executor.execute_tool(
    tool_name="search_code",
    tool_args={
        "apk_path": "/path/to/app.apk",
        "pattern": "addJavascriptInterface",
    }
)

print(f"Success: {result.success}")
print(f"Output: {result.output}")
print(f"Time: {result.execution_time_ms}ms")
```

### Tool Routing

Tools are automatically routed to the appropriate server:

```python
TOOL_TO_SERVER = {
    # JADX tools
    "decompile": "jadx",
    "search_code": "jadx",
    "get_class": "jadx",
    "find_security_patterns": "jadx",

    # Apktool tools
    "decode": "apktool",
    "get_manifest": "apktool",
    "get_smali": "apktool",
    "find_security_issues": "apktool",

    # ADB tools
    "adb_shell": "adb",
    "get_package_info": "adb",
}
```

### ToolResult

```python
@dataclass
class ToolResult:
    tool_name: str          # Name of the tool executed
    server_id: str          # MCP server that handled the request
    success: bool           # Whether execution succeeded
    output: Any             # Tool output (varies by tool)
    execution_time_ms: int  # Execution duration
    error: Optional[str]    # Error message if failed
```

---

## Integration with Praxis Loop

The MCP system provides **binary ground truth** for the Praxis calibration:

```python
from dojo.graders.praxis_runner import PraxisRunner
from dojo.mcp import MCPExecutor

# Initialize
executor = MCPExecutor()
await executor.initialize()

runner = PraxisRunner(
    llm_client=client,
    mcp_executor=executor,
)

# During Praxis Loop:
# 1. Model produces reasoning + verification tasks
# 2. MCPExecutor runs tasks against real tools
# 3. Results provide calibration signal
# 4. High confidence + failure = hallucination detected
```

### Verification Task Flow

```
Model Output
     │
     ▼
┌─────────────────┐
│ Verification    │
│ Task Extracted  │
│ - tool: search_code
│ - args: {pattern: "crypto"}
│ - expected: "AES usage found"
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ MCPExecutor     │
│ Routes to JADX  │
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Tool Result     │
│ - success: true
│ - output: [matches...]
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Calibration     │
│ Compare to      │
│ model confidence│
└─────────────────┘
```

---

## Configuration

### Server Configuration

```python
from dojo.mcp.config import MCPConfig, ServerConfig, load_config

# Load from config file
config = load_config(Path("dojo/mcp/config/servers.json"))

# Or create programmatically
config = MCPConfig(
    servers={
        "jadx": ServerConfig(
            command=["python", "-m", "dojo.mcp.servers.jadx_server"],
            env={"JADX_PATH": "/opt/jadx/bin/jadx"},
        ),
        "apktool": ServerConfig(
            command=["python", "-m", "dojo.mcp.servers.apktool_server"],
            env={"APKTOOL_PATH": "/usr/local/bin/apktool"},
        ),
    }
)
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JADX_PATH` | Path to JADX binary | `jadx` (from PATH) |
| `APKTOOL_PATH` | Path to Apktool binary | `apktool` (from PATH) |
| `MCP_OUTPUT_BASE` | Base directory for tool outputs | `/tmp/mcp_output` |

---

## Prerequisites

### Install JADX

```bash
# macOS
brew install jadx

# Linux
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d /opt/jadx
export PATH=$PATH:/opt/jadx/bin
```

### Install Apktool

```bash
# macOS
brew install apktool

# Linux
apt install apktool
```

---

## Quick Execute

For one-off tool executions:

```python
from dojo.mcp import quick_execute

# Execute without full initialization
result = await quick_execute(
    tool_name="get_manifest",
    tool_args={"apk_path": "app.apk"},
)
```

---

## Directory Structure

```
dojo/mcp/
├── __init__.py          # Public API exports
├── executor.py          # MCPExecutor, ToolResult, tool routing
├── server.py            # Base MCP server utilities
├── config/
│   ├── __init__.py
│   └── servers.json     # Server configurations
├── servers/
│   ├── __init__.py
│   ├── jadx_server.py   # JADX MCP server implementation
│   └── apktool_server.py # Apktool MCP server implementation
└── docker/              # Docker configurations for tools
```

---

## Error Handling

```python
from dojo.mcp import MCPExecutor, ToolResult

executor = MCPExecutor()
result = await executor.execute_tool("search_code", {"apk_path": "missing.apk"})

if not result.success:
    print(f"Tool failed: {result.error}")
    # Handle gracefully - this feeds into calibration
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Server not found` | MCP server not running | Start the server |
| `Tool not found` | Invalid tool name | Check TOOL_TO_SERVER mapping |
| `APK not found` | Invalid path | Verify APK path exists |
| `Timeout` | Long-running operation | Increase timeout or use async |

---

## Testing

```bash
# Run MCP integration tests
python -m pytest dojo/mcp/test_mcp_apk.py -v

# Test Praxis loop with MCP
python dojo/mcp/test_praxis_loop.py
```

### Manual Test

```python
import asyncio
from dojo.mcp import MCPExecutor

async def test():
    executor = MCPExecutor()
    await executor.initialize()

    result = await executor.execute_tool(
        "get_manifest",
        {"apk_path": "test.apk"}
    )
    print(result.to_dict())

asyncio.run(test())
```
