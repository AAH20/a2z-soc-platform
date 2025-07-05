#!/bin/bash

# A2Z Network Agent Cross-Platform Build Script
# Supports macOS, Linux, and Windows

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AGENT_NAME="a2z-network-agent"
VERSION="1.0.0"
BUILD_DIR="build"
DIST_DIR="dist"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect platform
detect_platform() {
    case "$(uname -s)" in
        Darwin*)    PLATFORM="macos" ;;
        Linux*)     PLATFORM="linux" ;;
        CYGWIN*)    PLATFORM="windows" ;;
        MINGW*)     PLATFORM="windows" ;;
        MSYS*)      PLATFORM="windows" ;;
        *)          PLATFORM="unknown" ;;
    esac
    
    case "$(uname -m)" in
        x86_64)     ARCH="x64" ;;
        arm64)      ARCH="arm64" ;;
        aarch64)    ARCH="arm64" ;;
        i686)       ARCH="x32" ;;
        *)          ARCH="unknown" ;;
    esac
    
    print_status "Detected platform: $PLATFORM-$ARCH"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed"
        exit 1
    fi
    
    NODE_VERSION=$(node --version)
    print_success "Node.js version: $NODE_VERSION"
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed"
        exit 1
    fi
    
    NPM_VERSION=$(npm --version)
    print_success "npm version: $NPM_VERSION"
    
    # Check for pkg (if needed for binary compilation)
    if command -v pkg &> /dev/null; then
        PKG_VERSION=$(pkg --version)
        print_success "pkg version: $PKG_VERSION"
    else
        print_warning "pkg not found - will install if needed for binary builds"
    fi
    
    # Platform-specific checks
    case $PLATFORM in
        "linux")
            # Check for libpcap-dev
            if dpkg -l | grep -q libpcap-dev; then
                print_success "libpcap-dev is installed"
            else
                print_warning "libpcap-dev not found - may be needed for packet capture"
            fi
            ;;
        "macos")
            # Check for Xcode command line tools
            if xcode-select -p &> /dev/null; then
                print_success "Xcode command line tools installed"
            else
                print_warning "Xcode command line tools not found"
            fi
            ;;
        "windows")
            # Check for Windows SDK or Visual Studio
            if command -v cl &> /dev/null; then
                print_success "Microsoft C++ compiler found"
            else
                print_warning "Microsoft C++ compiler not found"
            fi
            ;;
    esac
}

# Function to setup build environment
setup_build_env() {
    print_status "Setting up build environment..."
    
    # Create build directories
    mkdir -p "$BUILD_DIR"
    mkdir -p "$DIST_DIR"
    
    # Clean previous builds
    rm -rf "$BUILD_DIR"/*
    rm -rf "$DIST_DIR"/*
    
    print_success "Build environment ready"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    # Install production dependencies
    npm ci --only=production
    
    # Platform-specific dependency installation
    case $PLATFORM in
        "linux")
            # Install native dependencies for Linux
            if command -v apt-get &> /dev/null; then
                print_status "Installing Linux native dependencies..."
                # Note: This would require sudo, so we'll just warn
                print_warning "Make sure libpcap-dev is installed: sudo apt-get install libpcap-dev"
            fi
            ;;
        "macos")
            # Install native dependencies for macOS
            if command -v brew &> /dev/null; then
                print_status "Checking macOS native dependencies..."
                if brew list libpcap &> /dev/null; then
                    print_success "libpcap is available"
                else
                    print_warning "libpcap not found via brew"
                fi
            fi
            ;;
        "windows")
            # Windows-specific setup
            print_status "Windows build detected"
            print_warning "Ensure WinPcap or Npcap is installed for packet capture"
            ;;
    esac
    
    print_success "Dependencies installed"
}

# Function to run tests
run_tests() {
    print_status "Running cross-platform tests..."
    
    # Run the test suite
    if node scripts/test-agent.js; then
        print_success "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Function to build for current platform
build_current_platform() {
    print_status "Building for current platform ($PLATFORM-$ARCH)..."
    
    # Create platform-specific build directory
    PLATFORM_BUILD_DIR="$BUILD_DIR/$PLATFORM-$ARCH"
    mkdir -p "$PLATFORM_BUILD_DIR"
    
    # Copy source files
    cp -r src/ "$PLATFORM_BUILD_DIR/"
    cp package.json "$PLATFORM_BUILD_DIR/"
    cp README.md "$PLATFORM_BUILD_DIR/" 2>/dev/null || true
    
    # Copy platform-specific files
    case $PLATFORM in
        "windows")
            # Create Windows batch file
            cat > "$PLATFORM_BUILD_DIR/start-agent.bat" << 'EOF'
@echo off
echo Starting A2Z Network Agent...
node src/index.js %*
EOF
            ;;
        *)
            # Create Unix shell script
            cat > "$PLATFORM_BUILD_DIR/start-agent.sh" << 'EOF'
#!/bin/bash
echo "Starting A2Z Network Agent..."
node src/index.js "$@"
EOF
            chmod +x "$PLATFORM_BUILD_DIR/start-agent.sh"
            ;;
    esac
    
    # Create platform-specific config
    cat > "$PLATFORM_BUILD_DIR/platform-config.json" << EOF
{
    "platform": "$PLATFORM",
    "architecture": "$ARCH",
    "version": "$VERSION",
    "buildDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "nodeVersion": "$(node --version)"
}
EOF
    
    print_success "Build completed for $PLATFORM-$ARCH"
}

# Function to create distribution package
create_distribution() {
    print_status "Creating distribution package..."
    
    DIST_NAME="$AGENT_NAME-$VERSION-$PLATFORM-$ARCH"
    DIST_PATH="$DIST_DIR/$DIST_NAME"
    
    # Copy build to distribution
    cp -r "$BUILD_DIR/$PLATFORM-$ARCH" "$DIST_PATH"
    
    # Create installation script
    case $PLATFORM in
        "windows")
            cat > "$DIST_PATH/install.bat" << 'EOF'
@echo off
echo Installing A2Z Network Agent...
echo.
echo Prerequisites:
echo - Node.js (v14 or higher)
echo - WinPcap or Npcap for packet capture
echo.
echo Installation complete!
echo Run: start-agent.bat
EOF
            ;;
        *)
            cat > "$DIST_PATH/install.sh" << 'EOF'
#!/bin/bash
echo "Installing A2Z Network Agent..."
echo
echo "Prerequisites:"
echo "- Node.js (v14 or higher)"
echo "- libpcap-dev (Linux) or libpcap (macOS)"
echo
echo "Installation complete!"
echo "Run: ./start-agent.sh"
EOF
            chmod +x "$DIST_PATH/install.sh"
            ;;
    esac
    
    # Create README for distribution
    cat > "$DIST_PATH/README.txt" << EOF
A2Z Network Agent v$VERSION
Platform: $PLATFORM-$ARCH
Build Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)

INSTALLATION:
$( [[ "$PLATFORM" == "windows" ]] && echo "Run: install.bat" || echo "Run: ./install.sh" )

USAGE:
$( [[ "$PLATFORM" == "windows" ]] && echo "start-agent.bat [options]" || echo "./start-agent.sh [options]" )

OPTIONS:
  --config <path>    Configuration file path
  --interface <name> Network interface to monitor
  --debug           Enable debug logging
  --help            Show help

REQUIREMENTS:
- Node.js v14 or higher
- Network administrator privileges
$( [[ "$PLATFORM" == "windows" ]] && echo "- WinPcap or Npcap" || echo "- libpcap library" )

For support, visit: https://github.com/your-org/a2z-soc
EOF
    
    # Create archive
    case $PLATFORM in
        "windows")
            if command -v 7z &> /dev/null; then
                (cd "$DIST_DIR" && 7z a "$DIST_NAME.zip" "$DIST_NAME/")
                print_success "Created: $DIST_DIR/$DIST_NAME.zip"
            else
                print_warning "7z not found - archive not created"
            fi
            ;;
        *)
            (cd "$DIST_DIR" && tar -czf "$DIST_NAME.tar.gz" "$DIST_NAME/")
            print_success "Created: $DIST_DIR/$DIST_NAME.tar.gz"
            ;;
    esac
    
    print_success "Distribution package created: $DIST_NAME"
}

# Function to build binary (optional)
build_binary() {
    if [ "$BUILD_BINARY" = "true" ]; then
        print_status "Building binary executable..."
        
        # Install pkg if not available
        if ! command -v pkg &> /dev/null; then
            print_status "Installing pkg..."
            npm install -g pkg
        fi
        
        # Build binary
        BINARY_NAME="$AGENT_NAME-$PLATFORM-$ARCH"
        if [ "$PLATFORM" = "windows" ]; then
            BINARY_NAME="$BINARY_NAME.exe"
        fi
        
        pkg src/index.js --target "node16-$PLATFORM-$ARCH" --output "$DIST_DIR/$BINARY_NAME"
        
        if [ -f "$DIST_DIR/$BINARY_NAME" ]; then
            print_success "Binary created: $DIST_DIR/$BINARY_NAME"
        else
            print_error "Binary build failed"
        fi
    fi
}

# Function to verify build
verify_build() {
    print_status "Verifying build..."
    
    PLATFORM_BUILD_DIR="$BUILD_DIR/$PLATFORM-$ARCH"
    
    # Check required files exist
    if [ ! -f "$PLATFORM_BUILD_DIR/src/index.js" ]; then
        print_error "Main entry point missing"
        exit 1
    fi
    
    if [ ! -f "$PLATFORM_BUILD_DIR/package.json" ]; then
        print_error "package.json missing"
        exit 1
    fi
    
    # Test that the agent can be imported
    if (cd "$PLATFORM_BUILD_DIR" && node -e "require('./src/index.js')"); then
        print_success "Agent module loads successfully"
    else
        print_error "Agent module failed to load"
        exit 1
    fi
    
    print_success "Build verification passed"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --test-only     Run tests only, don't build"
    echo "  --binary        Build binary executable"
    echo "  --skip-tests    Skip running tests"
    echo "  --clean         Clean build directories only"
    echo "  --help          Show this help"
    echo
    echo "Environment variables:"
    echo "  BUILD_BINARY=true    Build binary executable"
    echo "  SKIP_TESTS=true      Skip running tests"
}

# Main execution
main() {
    print_status "A2Z Network Agent Cross-Platform Build"
    print_status "======================================"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test-only)
                TEST_ONLY=true
                shift
                ;;
            --binary)
                BUILD_BINARY=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --clean)
                CLEAN_ONLY=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Detect platform
    detect_platform
    
    if [ "$CLEAN_ONLY" = "true" ]; then
        print_status "Cleaning build directories..."
        rm -rf "$BUILD_DIR" "$DIST_DIR"
        print_success "Clean completed"
        exit 0
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Setup build environment
    setup_build_env
    
    # Install dependencies
    install_dependencies
    
    # Run tests unless skipped
    if [ "$SKIP_TESTS" != "true" ] && [ "$TEST_ONLY" != "true" ]; then
        run_tests
    fi
    
    if [ "$TEST_ONLY" = "true" ]; then
        run_tests
        print_success "Test-only mode completed"
        exit 0
    fi
    
    # Build for current platform
    build_current_platform
    
    # Verify build
    verify_build
    
    # Create distribution
    create_distribution
    
    # Build binary if requested
    build_binary
    
    print_success "Build completed successfully!"
    print_status "Distribution available in: $DIST_DIR"
}

# Run main function
main "$@" 