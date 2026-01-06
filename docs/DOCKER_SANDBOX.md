# Docker Sandbox Execution

AgenticART supports running generated exploit scripts in isolated Docker containers, providing a security boundary between LLM-generated code and your host system.

## Execution Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `DRY_RUN` | Validates script syntax without execution | Testing prompts, reviewing generated code |
| `DOCKER` | Runs in isolated container with ADB access | **Recommended for most use cases** |
| `LIVE` | Executes directly on host (no isolation) | Trusted scripts, debugging |

## Why Use Docker Mode?

LLM-generated code is unpredictable. Even with prompt engineering, models can produce scripts that:

- Execute unintended shell commands
- Access files outside the intended scope
- Consume excessive resources
- Contain logic errors with destructive side effects

Docker mode contains these risks while still allowing full interaction with the Android emulator via ADB.

## Security Features

The Docker sandbox enforces multiple layers of isolation:

| Protection | Implementation |
|------------|----------------|
| Non-root execution | Runs as `pentester` user (UID 1000) |
| Read-only filesystem | Container root is immutable |
| Capability dropping | All capabilities dropped except `NET_RAW` |
| No privilege escalation | `--security-opt no-new-privileges` |
| Memory limit | 512MB default (configurable) |
| CPU limit | 50% of one core |
| Network isolation | Internal network, no internet access |
| Auto-cleanup | Containers removed after execution |
| Tmpfs only | Writable dirs use tmpfs with `noexec` |

## Setup

### 1. Build the Sandbox Image

```bash
docker-compose build sandbox
```

### 2. Create the Sandbox Network

```bash
docker network create --internal agentic-sandbox-net
```

The `--internal` flag blocks internet access while allowing communication with the Android emulator.

### 3. Configure Emulator Access

Set the emulator device in your environment:

```bash
export EMULATOR_DEVICE="host.docker.internal:5555"
```

For Genymotion or other network-accessible emulators, use the appropriate IP:port.

## Usage

### Web Interface

Select **"Docker Sandbox (Recommended)"** in the sidebar execution mode dropdown.

### Python API

```python
from core.exploitation import ExploitRunner, ExecutionMode

# Create runner with Docker mode
runner = ExploitRunner(mode=ExecutionMode.DOCKER, timeout=300)

# Execute a script
result = runner.execute("path/to/script.py")

print(f"Success: {result.success}")
print(f"Output: {result.stdout}")
```

### CLI

```bash
python -m dojo.test_end_to_end --mode docker --belt white
```

## Configuration

Environment variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_SANDBOX_IMAGE` | `agentic-sandbox:latest` | Container image to use |
| `DOCKER_SANDBOX_NETWORK` | `agentic-sandbox-net` | Docker network name |
| `DOCKER_SANDBOX_MEMORY` | `512m` | Memory limit |
| `EMULATOR_DEVICE` | `host.docker.internal:5555` | ADB device connection |

### Programmatic Configuration

```python
from core.exploitation import DockerExecutor, DockerConfig

config = DockerConfig(
    image_name="agentic-sandbox:latest",
    network="agentic-sandbox-net",
    memory_limit="1g",  # Increase for heavy scripts
    cpu_quota=100000,   # 100% of one core
    emulator_device="192.168.56.101:5555",
)

executor = DockerExecutor(config=config, timeout=600)
```

## Verifying Sandbox Status

Check if Docker sandbox is properly configured:

```python
from core.exploitation import DockerExecutor

executor = DockerExecutor()
available, message = executor.check_docker_available()

if available:
    print("Docker sandbox ready")
else:
    print(f"Setup required: {message}")
```

Common issues:
- `"Docker daemon not running"` - Start Docker Desktop or dockerd
- `"Sandbox image not found"` - Run `docker-compose build sandbox`
- `"Sandbox network not found"` - Run `docker network create --internal agentic-sandbox-net`

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HOST SYSTEM                             │
│                                                                 │
│  ┌──────────────┐      ┌──────────────────────────────────┐    │
│  │ AgenticART   │      │     Docker Container             │    │
│  │              │      │   ┌────────────────────────┐     │    │
│  │ ExploitRunner│─────▶│   │ /workspace/script.py  │     │    │
│  │              │      │   │ (read-only mount)      │     │    │
│  └──────────────┘      │   └──────────┬─────────────┘     │    │
│                        │              │                    │    │
│                        │              ▼                    │    │
│                        │   ┌────────────────────────┐     │    │
│                        │   │   python3 script.py    │     │    │
│                        │   │   (as pentester user)  │     │    │
│                        │   └──────────┬─────────────┘     │    │
│                        │              │                    │    │
│                        │   sandbox-net (internal)          │    │
│                        └──────────────┼────────────────────┘    │
│                                       │                         │
│                                       │ ADB commands            │
│                                       ▼                         │
│                        ┌──────────────────────────────────┐    │
│                        │      Android Emulator            │    │
│                        │      (Genymotion/AVD)            │    │
│                        └──────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Flow:**
1. Script is mounted read-only into container
2. Container runs with restricted permissions
3. Script executes ADB commands over internal network
4. Results captured and returned to host
5. Container automatically removed

## Limitations

- **No GUI tools**: Container is headless, no X11 forwarding
- **No persistent state**: Each execution starts fresh
- **Network restricted**: Cannot reach internet (only emulator)
- **Resource limits**: May need adjustment for resource-intensive scripts

## Troubleshooting

### Container times out

Increase timeout:
```python
runner = ExploitRunner(mode=ExecutionMode.DOCKER, timeout=600)
```

### ADB connection refused

Verify emulator is accessible from Docker:
```bash
docker run --rm --network agentic-sandbox-net agentic-sandbox:latest \
    adb connect host.docker.internal:5555
```

### Permission denied errors

The sandbox runs as non-root. If your script requires root operations on the device (not container), use `adb shell su` commands - the Android emulator can still be rooted.

### Out of memory

Increase memory limit:
```python
config = DockerConfig(memory_limit="1g")
```
