#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LLM-AndroidPentest Setup Script
# Automates environment setup for macOS, Linux, and WSL
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Get project root (parent of scripts directory)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

# Header
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║           LLM-AndroidPentest Setup Script                            ║"
echo "║           Automated environment configuration                        ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if grep -q Microsoft /proc/version 2>/dev/null; then
            OS="wsl"
        else
            OS="linux"
        fi
    else
        OS="unknown"
    fi
    log_info "Detected OS: $OS"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing=()

    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        log_success "Python $PYTHON_VERSION found"
    else
        missing+=("python3")
    fi

    # Check Docker
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
        log_success "Docker $DOCKER_VERSION found"
    else
        missing+=("docker")
    fi

    # Check Docker Compose
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        log_success "Docker Compose found"
    else
        missing+=("docker-compose")
    fi

    # Check ADB
    if command -v adb &> /dev/null; then
        ADB_VERSION=$(adb version | head -1)
        log_success "ADB found: $ADB_VERSION"
    else
        log_warning "ADB not found - will install via brew"
        missing+=("android-platform-tools")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing prerequisites: ${missing[*]}"
        log_info "Please install missing tools and re-run this script"
        exit 1
    fi
}

# Install system tools via Homebrew (macOS)
install_system_tools() {
    log_info "Installing system security tools..."

    if [[ "$OS" != "macos" ]]; then
        log_warning "Automatic tool installation only supported on macOS"
        log_info "For Linux, see TOOLS.md for manual installation commands"
        return
    fi

    # Check for Homebrew
    if ! command -v brew &> /dev/null; then
        log_error "Homebrew not found. Install from https://brew.sh"
        return 1
    fi

    # Tools to install via brew
    local brew_tools=(
        "android-platform-tools"  # adb, fastboot
        "apktool"                 # APK reverse engineering
        "jadx"                    # DEX to Java decompiler
        "nmap"                    # Network scanning
    )

    for tool in "${brew_tools[@]}"; do
        if brew list "$tool" &>/dev/null; then
            log_success "$tool already installed"
        else
            log_info "Installing $tool..."
            brew install "$tool" && log_success "$tool installed" || log_warning "Failed to install $tool"
        fi
    done

    # Optional cask tools (GUI applications)
    echo ""
    log_info "Optional GUI tools (install manually if needed):"
    echo "  brew install --cask owasp-zap        # Web app security testing"
    echo "  brew install --cask burp-suite       # HTTP proxy (requires license)"
    echo "  brew install --cask genymotion       # Android emulator"
    echo ""
}

# Setup Python virtual environment
setup_python_env() {
    log_info "Setting up Python virtual environment..."

    VENV_DIR="${PROJECT_ROOT}/venv"

    if [ -d "$VENV_DIR" ]; then
        log_warning "Virtual environment already exists"
        read -p "Recreate? (y/n): " recreate
        if [ "$recreate" = "y" ]; then
            rm -rf "$VENV_DIR"
        else
            log_info "Using existing virtual environment"
            source "$VENV_DIR/bin/activate"
            return
        fi
    fi

    log_info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    log_info "Upgrading pip..."
    pip install --upgrade pip

    log_info "Installing Python dependencies (this may take a few minutes)..."
    pip install -r requirements.txt

    # Create activation helper script
    create_activation_script

    log_success "Python environment configured"
    log_info "Activate with: source venv/bin/activate"
}

# Create convenient activation script
create_activation_script() {
    log_info "Creating activation helper..."

    cat > "${PROJECT_ROOT}/activate.sh" << 'ACTIVATE_EOF'
#!/bin/bash
# LLM-AndroidPentest Environment Activation
# Usage: source activate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "Error: Virtual environment not found. Run ./scripts/setup.sh first."
    return 1
fi

source "$SCRIPT_DIR/venv/bin/activate"

# Set project root
export LLM_PENTEST_ROOT="$SCRIPT_DIR"

# Add scripts to PATH
export PATH="$SCRIPT_DIR/scripts:$PATH"

echo "✓ LLM-AndroidPentest environment activated"
echo "  Python: $(which python3)"
echo "  Project: $LLM_PENTEST_ROOT"
echo ""
echo "Quick commands:"
echo "  streamlit run webapp/app.py     # Start web UI"
echo "  python -m pytest tests/         # Run tests"
echo "  ./scripts/check-tools.sh        # Verify tools"
ACTIVATE_EOF

    chmod +x "${PROJECT_ROOT}/activate.sh"
    log_success "Created activate.sh"
}

# Setup configuration files
setup_config() {
    log_info "Setting up configuration..."

    if [ ! -f "config/.env" ]; then
        cp config/.env.example config/.env
        log_success "Created config/.env from template"
        log_warning "Please edit config/.env to add your API keys"
    else
        log_info "config/.env already exists"
    fi

    # Create output directories
    mkdir -p output/{logs,reports,artifacts}
    mkdir -p scripts/generated

    log_success "Directories created"
}

# Setup Docker environment
setup_docker() {
    log_info "Building Docker images..."

    docker-compose build webapp

    log_success "Docker images built"
}

# Setup Genymotion (guidance only - manual installation required)
setup_genymotion_guidance() {
    log_info "Genymotion Setup Instructions"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Genymotion must be installed manually. Follow these steps:"
    echo ""
    echo "1. Download Genymotion Desktop from:"
    echo "   https://www.genymotion.com/download/"
    echo ""
    echo "2. Install and create an account (free tier available)"
    echo ""
    echo "3. Create a virtual device:"
    echo "   - Recommended: Google Pixel 7 - Android 13"
    echo "   - Enable 'Use virtual device network' or 'Bridge mode'"
    echo ""
    echo "4. Start the virtual device"
    echo ""
    echo "5. Enable ADB over network:"
    echo "   - Settings > Developer options > ADB over network"
    echo "   - Note the IP address (usually 192.168.56.101)"
    echo ""
    echo "6. Connect via ADB:"
    echo "   adb connect 192.168.56.101:5555"
    echo ""
    echo "7. Update config/.env with the correct IP"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Verify ADB connection
verify_adb() {
    log_info "Checking ADB connection..."

    EMULATOR_IP="${EMULATOR_IP:-192.168.56.101}"
    EMULATOR_PORT="${EMULATOR_PORT:-5555}"

    if adb connect "$EMULATOR_IP:$EMULATOR_PORT" 2>/dev/null | grep -q "connected"; then
        log_success "Connected to emulator at $EMULATOR_IP:$EMULATOR_PORT"

        # Get device info
        DEVICE_INFO=$(adb -s "$EMULATOR_IP:$EMULATOR_PORT" shell getprop ro.product.model 2>/dev/null)
        if [ -n "$DEVICE_INFO" ]; then
            log_success "Device: $DEVICE_INFO"
        fi
    else
        log_warning "Could not connect to emulator at $EMULATOR_IP:$EMULATOR_PORT"
        log_info "Make sure Genymotion is running with ADB over network enabled"
    fi
}

# Run initial tests
run_tests() {
    log_info "Running tests..."

    if [ -d "venv" ]; then
        source venv/bin/activate
    fi

    pytest tests/ -v --tb=short || log_warning "Some tests failed (expected without emulator)"
}

# Main setup flow
main() {
    detect_os
    check_prerequisites

    echo ""
    echo "Select setup mode:"
    echo "  1) Full setup (System tools + Python venv + Docker)"
    echo "  2) Python venv only (requires system tools already installed)"
    echo "  3) System tools only (brew packages)"
    echo "  4) Docker only (containerized)"
    echo "  5) Verify existing setup"
    echo ""
    read -p "Choice [1-5]: " choice

    case $choice in
        1)
            install_system_tools
            setup_python_env
            setup_config
            setup_docker
            setup_genymotion_guidance
            ;;
        2)
            setup_python_env
            setup_config
            ;;
        3)
            install_system_tools
            ;;
        4)
            setup_config
            setup_docker
            ;;
        5)
            verify_adb
            run_tests
            ./scripts/check-tools.sh 2>/dev/null || log_warning "check-tools.sh not found"
            ;;
        *)
            log_error "Invalid choice"
            exit 1
            ;;
    esac

    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                        Setup Complete!                               ║"
    echo "╠══════════════════════════════════════════════════════════════════════╣"
    echo "║                                                                      ║"
    echo "║  Next steps:                                                         ║"
    echo "║                                                                      ║"
    echo "║  1. Activate the environment:                                        ║"
    echo "║     source activate.sh                                               ║"
    echo "║                                                                      ║"
    echo "║  2. Add your API key to config/.env:                                 ║"
    echo "║     ANTHROPIC_API_KEY=sk-ant-...                                     ║"
    echo "║     OPENAI_API_KEY=sk-your-key-here                                  ║"
    echo "║                                                                      ║"
    echo "║  3. Start Genymotion and create a virtual device                     ║"
    echo "║                                                                      ║"
    echo "║  4. Run the application:                                             ║"
    echo "║     streamlit run webapp/app.py                                      ║"
    echo "║                                                                      ║"
    echo "║  5. Verify tools are installed:                                      ║"
    echo "║     ./scripts/check-tools.sh                                         ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
}

main "$@"
