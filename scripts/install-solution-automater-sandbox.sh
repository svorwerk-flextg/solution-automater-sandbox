#!/bin/bash

# =============================================================================
# SOLUTION-AUTOMATER-SANDBOX ONE-COMMAND INSTALLER
# Idiot-proof setup for enterprise AI agent orchestration platform
# =============================================================================

set -euo pipefail

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================
SAS_VERSION="1.0.0"
SAS_REPO_URL="https://github.com/solution-automater-sandbox/claude-docker.git"
SAS_HOME="${HOME}/.solution-automater-sandbox"
INSTALL_DIR="${HOME}/solution-automater-sandbox"

# Colors and emojis for better UX
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

SUCCESS="✅"
ERROR="❌"
WARNING="⚠️"
INFO="ℹ️"
ROCKET="🚀"
GEAR="⚙️"
SHIELD="🛡️"
CLOUD="☁️"
SPARKLES="✨"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
log_info() {
    echo -e "${BLUE}${INFO} $1${NC}"
}

log_success() {
    echo -e "${GREEN}${SUCCESS} $1${NC}"
}

log_error() {
    echo -e "${RED}${ERROR} $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}${WARNING} $1${NC}"
}

log_section() {
    echo -e "\n${PURPLE}${GEAR} $1${NC}\n"
}

show_banner() {
    cat << 'EOF'

███████╗ ██████╗ ██╗     ██╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗
██╔════╝██╔═══██╗██║     ██║   ██║╚══██╔══╝██║██╔═══██╗████╗  ██║
███████╗██║   ██║██║     ██║   ██║   ██║   ██║██║   ██║██╔██╗ ██║
╚════██║██║   ██║██║     ██║   ██║   ██║   ██║██║   ██║██║╚██╗██║
███████║╚██████╔╝███████╗╚██████╔╝   ██║   ██║╚██████╔╝██║ ╚████║
╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝    ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

 █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗███████╗██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██╔████╔██║███████║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗
██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
███████╗███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║ ╚███╔╝ 
╚════██║██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║ ██╔██╗ 
███████║██║  ██║██║ ╚████║██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝

EOF
    echo -e "${CYAN}Enterprise AI Agent Orchestration Platform${NC}"
    echo -e "${GREEN}Version $SAS_VERSION${NC}"
    echo -e "${PURPLE}Production-Ready • Secure • Scalable${NC}\n"
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================
check_operating_system() {
    log_info "Checking operating system..."
    
    case "$(uname -s)" in
        Linux*)
            OS="Linux"
            DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
            log_success "Operating System: $OS ($DISTRO)"
            ;;
        Darwin*)
            OS="macOS"
            VERSION=$(sw_vers -productVersion)
            log_success "Operating System: $OS ($VERSION)"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="Windows"
            log_success "Operating System: $OS (WSL/Git Bash)"
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
}

check_shell() {
    log_info "Checking shell environment..."
    
    if [ -n "${BASH_VERSION:-}" ]; then
        log_success "Shell: Bash $BASH_VERSION"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        log_success "Shell: Zsh $ZSH_VERSION"
    else
        log_warning "Shell: $(basename "$SHELL") (may have limited compatibility)"
    fi
}

check_user_permissions() {
    log_info "Checking user permissions..."
    
    # Check if user can write to home directory
    if [ -w "$HOME" ]; then
        log_success "Home directory is writable"
    else
        log_error "Home directory is not writable"
        exit 1
    fi
    
    # Check if user is in docker group (if Docker is installed)
    if command -v docker >/dev/null 2>&1; then
        if groups | grep -q docker; then
            log_success "User is in docker group"
        else
            log_warning "User is not in docker group - may need sudo for Docker commands"
        fi
    fi
}

check_prerequisites() {
    log_section "Checking Prerequisites ${SHIELD}"
    
    check_operating_system
    check_shell
    check_user_permissions
    
    local missing_deps=()
    local optional_deps=()
    
    # Required dependencies
    local required_commands=("curl" "git" "docker" "docker" "jq")
    local required_descriptions=("HTTP client" "Version control" "Container runtime" "Container composition" "JSON processor")
    
    for i in "${!required_commands[@]}"; do
        local cmd="${required_commands[$i]}"
        local desc="${required_descriptions[$i]}"
        
        if command -v "$cmd" >/dev/null 2>&1; then
            local version=$($cmd --version 2>/dev/null | head -1 || echo "unknown")
            log_success "$desc ($cmd): available"
            log_info "  Version: $version"
        else
            missing_deps+=("$cmd ($desc)")
        fi
    done
    
    # Check Docker Compose specifically
    if docker compose version >/dev/null 2>&1; then
        local compose_version=$(docker compose version --short)
        log_success "Docker Compose: available ($compose_version)"
    else
        missing_deps+=("docker-compose")
    fi
    
    # Optional but recommended
    local optional_commands=("aws" "az" "yq" "helm")
    local optional_descriptions=("AWS CLI" "Azure CLI" "YAML processor" "Kubernetes package manager")
    
    for i in "${!optional_commands[@]}"; do
        local cmd="${optional_commands[$i]}"
        local desc="${optional_descriptions[$i]}"
        
        if command -v "$cmd" >/dev/null 2>&1; then
            local version=$($cmd --version 2>/dev/null | head -1 || echo "unknown")
            log_success "$desc ($cmd): available"
        else
            optional_deps+=("$cmd ($desc)")
        fi
    done
    
    # Handle missing required dependencies
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo ""
        show_installation_instructions "${missing_deps[@]}"
        exit 1
    fi
    
    # Show optional dependencies
    if [ ${#optional_deps[@]} -ne 0 ]; then
        log_info "Optional dependencies not found:"
        for dep in "${optional_deps[@]}"; do
            echo "  - $dep"
        done
        echo -e "\n${CYAN}These are optional but recommended for full functionality${NC}"
    fi
}

show_installation_instructions() {
    local missing_deps=("$@")
    
    echo -e "${YELLOW}Installation instructions:${NC}\n"
    
    case "$OS" in
        "Linux")
            echo -e "${CYAN}Ubuntu/Debian:${NC}"
            echo "sudo apt-get update"
            echo "sudo apt-get install curl git jq"
            echo ""
            echo -e "${CYAN}Docker Installation:${NC}"
            echo "curl -fsSL https://get.docker.com -o get-docker.sh"
            echo "sudo sh get-docker.sh"
            echo "sudo usermod -aG docker \$USER"
            echo ""
            echo -e "${CYAN}CentOS/RHEL/Fedora:${NC}"
            echo "sudo yum install curl git jq"
            echo "# Follow Docker installation guide for your distribution"
            ;;
        "macOS")
            echo -e "${CYAN}Using Homebrew:${NC}"
            echo "brew install curl git jq"
            echo ""
            echo -e "${CYAN}Docker Desktop:${NC}"
            echo "Download from: https://www.docker.com/products/docker-desktop"
            ;;
        "Windows")
            echo -e "${CYAN}Using Chocolatey:${NC}"
            echo "choco install git curl jq docker-desktop"
            echo ""
            echo -e "${CYAN}Using Scoop:${NC}"
            echo "scoop install git curl jq"
            echo "# Install Docker Desktop manually"
            ;;
    esac
    
    echo -e "\n${CYAN}After installation, restart your terminal and run this installer again.${NC}"
}

# =============================================================================
# DOCKER ENVIRONMENT CHECKS
# =============================================================================
check_docker_environment() {
    log_section "Checking Docker Environment ${ROCKET}"
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        echo -e "\n${CYAN}Please start Docker and try again:${NC}"
        case "$OS" in
            "Linux")
                echo "sudo systemctl start docker"
                ;;
            "macOS"|"Windows")
                echo "Start Docker Desktop application"
                ;;
        esac
        exit 1
    fi
    
    log_success "Docker daemon is running"
    
    # Check Docker version
    local docker_version=$(docker version --format '{{.Server.Version}}')
    log_info "Docker version: $docker_version"
    
    # Check Docker Compose
    local compose_version=$(docker compose version --short)
    log_info "Docker Compose version: $compose_version"
    
    # Check available resources
    local docker_info=$(docker system df 2>/dev/null || echo "Could not get Docker disk usage")
    log_info "Docker system info retrieved"
    
    # Test Docker functionality
    log_info "Testing Docker functionality..."
    if docker run --rm hello-world >/dev/null 2>&1; then
        log_success "Docker is working correctly"
    else
        log_error "Docker test failed"
        exit 1
    fi
}

# =============================================================================
# AUTHENTICATION CHECKS
# =============================================================================
check_claude_authentication() {
    log_section "Checking Claude Authentication ${SPARKLES}"
    
    # Check for Claude installation
    if ! command -v claude >/dev/null 2>&1; then
        log_error "Claude Code CLI not found"
        echo -e "\n${CYAN}Install Claude Code CLI:${NC}"
        echo "npm install -g @anthropic-ai/claude-code"
        echo ""
        echo -e "${CYAN}Then authenticate:${NC}"
        echo "claude"
        exit 1
    fi
    
    local claude_version=$(claude --version 2>/dev/null || echo "unknown")
    log_success "Claude Code CLI: available ($claude_version)"
    
    # Check authentication
    if [ -f "$HOME/.claude.json" ]; then
        log_success "Claude authentication found"
        
        # Validate authentication file
        if [ -s "$HOME/.claude.json" ]; then
            if python3 -c "import json; json.load(open('$HOME/.claude.json'))" 2>/dev/null; then
                log_success "Authentication file is valid"
            else
                log_error "Authentication file is corrupted"
                echo -e "\n${CYAN}Re-authenticate Claude:${NC}"
                echo "claude"
                exit 1
            fi
        else
            log_error "Authentication file is empty"
            echo -e "\n${CYAN}Authenticate Claude:${NC}"
            echo "claude"
            exit 1
        fi
    else
        log_error "Claude authentication not found"
        echo -e "\n${CYAN}Authenticate Claude Code:${NC}"
        echo "claude"
        echo ""
        echo -e "${YELLOW}After authentication, run this installer again.${NC}"
        exit 1
    fi
}

check_git_configuration() {
    log_info "Checking Git configuration..."
    
    local git_user=$(git config --global user.name 2>/dev/null || echo "")
    local git_email=$(git config --global user.email 2>/dev/null || echo "")
    
    if [ -n "$git_user" ] && [ -n "$git_email" ]; then
        log_success "Git configured: $git_user <$git_email>"
        export GIT_USER_NAME="$git_user"
        export GIT_USER_EMAIL="$git_email"
    else
        log_error "Git user not configured"
        echo -e "\n${CYAN}Configure Git:${NC}"
        echo "git config --global user.name \"Your Name\""
        echo "git config --global user.email \"your.email@example.com\""
        exit 1
    fi
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================
create_directory_structure() {
    log_section "Creating Directory Structure ${GEAR}"
    
    # Create SAS home directory
    log_info "Creating SAS home directory: $SAS_HOME"
    mkdir -p "$SAS_HOME"/{config,data,logs,cache,scripts,backups}
    mkdir -p "$SAS_HOME"/claude-home/.claude
    
    # Create installation directory
    log_info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    
    log_success "Directory structure created"
}

clone_repository() {
    log_section "Cloning Repository ${ROCKET}"
    
    if [ -d "$INSTALL_DIR/.git" ]; then
        log_info "Repository already exists, updating..."
        cd "$INSTALL_DIR"
        git fetch origin
        git reset --hard origin/main
    else
        log_info "Cloning repository from $SAS_REPO_URL"
        git clone "$SAS_REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    log_success "Repository ready"
}

setup_environment_configuration() {
    log_section "Setting Up Environment Configuration ${GEAR}"
    
    local env_file="$INSTALL_DIR/.env.solution-automater-sandbox"
    
    log_info "Creating environment configuration..."
    
    # Generate secure passwords
    local vault_token=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local redis_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local grafana_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    cat > "$env_file" << EOF
# =============================================================================
# SOLUTION-AUTOMATER-SANDBOX ENVIRONMENT CONFIGURATION
# Generated on: $(date)
# =============================================================================

# Core Configuration
SAS_VERSION=$SAS_VERSION
SAS_HOME=$SAS_HOME
HOST_UID=$(id -u)
HOST_GID=$(id -g)
GIT_USER_NAME=$GIT_USER_NAME
GIT_USER_EMAIL=$GIT_USER_EMAIL

# Security Configuration
VAULT_ROOT_TOKEN=$vault_token
REDIS_PASSWORD=$redis_password
GRAFANA_ADMIN_PASSWORD=$grafana_password

# Database Safety Configuration
DB_SAFETY_ENABLED=true
DB_SAFETY_LOG_LEVEL=INFO
DB_SAFETY_AUDIT_ENABLED=true

# System Configuration
SYSTEM_PACKAGES=""
DOCKER_MEMORY_LIMIT=8g
DOCKER_GPU_ACCESS=""

# Performance Configuration
MAX_CONCURRENT_AGENTS=10
MONITORING_ENABLED=true
SECURITY_ENABLED=true

# Cloud Integration (Optional - add your credentials)
# FABRIC_WORKSPACE_ID=your_fabric_workspace_id
# AWS_ACCESS_KEY_ID=your_aws_access_key
# AWS_SECRET_ACCESS_KEY=your_aws_secret_key
# AWS_DEFAULT_REGION=us-east-1

# API Keys (Optional - add your API keys)
# ANTHROPIC_API_KEY=your_anthropic_key
# OPENAI_API_KEY=your_openai_key
# TWILIO_ACCOUNT_SID=your_twilio_sid
# TWILIO_AUTH_TOKEN=your_twilio_token
# TWILIO_FROM_NUMBER=+1234567890
# TWILIO_TO_NUMBER=+0987654321

# Development Configuration
SAS_DEBUG=false
SAS_LOG_LEVEL=INFO
EOF
    
    # Copy Claude authentication
    log_info "Copying Claude authentication..."
    cp "$HOME/.claude.json" "$INSTALL_DIR/.claude.json"
    
    log_success "Environment configuration created"
    
    # Store credentials for user
    echo -e "\n${PURPLE}${SPARKLES} Generated Credentials ${SPARKLES}${NC}"
    echo -e "${CYAN}Grafana Admin Password:${NC} $grafana_password"
    echo -e "${CYAN}These credentials are saved in:${NC} $env_file"
    echo ""
}

install_cli_tool() {
    log_section "Installing CLI Tool ${GEAR}"
    
    local sas_cli="$INSTALL_DIR/bin/sas"
    local system_bin="/usr/local/bin/sas"
    
    if [ -f "$sas_cli" ]; then
        log_info "Installing SAS CLI to system..."
        
        # Try to install to system path
        if sudo cp "$sas_cli" "$system_bin" 2>/dev/null; then
            sudo chmod +x "$system_bin"
            log_success "SAS CLI installed to $system_bin"
        else
            # Fallback to user bin
            local user_bin="$HOME/.local/bin"
            mkdir -p "$user_bin"
            cp "$sas_cli" "$user_bin/sas"
            chmod +x "$user_bin/sas"
            log_success "SAS CLI installed to $user_bin/sas"
            
            # Add to PATH if not already there
            if [[ ":$PATH:" != *":$user_bin:"* ]]; then
                echo "export PATH=\"$user_bin:\$PATH\"" >> "$HOME/.bashrc"
                echo "export PATH=\"$user_bin:\$PATH\"" >> "$HOME/.zshrc" 2>/dev/null || true
                log_info "Added $user_bin to PATH in shell configuration"
            fi
        fi
    else
        log_error "SAS CLI not found in repository"
        exit 1
    fi
}

setup_shell_integration() {
    log_section "Setting Up Shell Integration ${GEAR}"
    
    local shells=("$HOME/.bashrc" "$HOME/.zshrc")
    
    for shell_config in "${shells[@]}"; do
        if [ -f "$shell_config" ]; then
            log_info "Configuring $(basename "$shell_config")..."
            
            # Add SAS configuration
            if ! grep -q "Solution-Automater-Sandbox" "$shell_config"; then
                cat >> "$shell_config" << EOF

# Solution-Automater-Sandbox Configuration
export SAS_HOME="$SAS_HOME"
export SAS_INSTALL_DIR="$INSTALL_DIR"
export PATH="$HOME/.local/bin:\$PATH"

# SAS Aliases
alias sas-start='sas start'
alias sas-stop='sas stop'
alias sas-status='sas status'
alias sas-logs='sas logs'
alias sas-monitor='sas monitor'

# Quick navigation
alias cd-sas='cd $INSTALL_DIR'
alias cd-sas-home='cd $SAS_HOME'

EOF
                log_success "$(basename "$shell_config") configured"
            else
                log_info "$(basename "$shell_config") already configured"
            fi
        fi
    done
    
    log_success "Shell integration completed"
}

build_initial_images() {
    log_section "Building Initial Images ${ROCKET}"
    
    cd "$INSTALL_DIR"
    
    log_info "Building Solution-Automater-Sandbox images (this may take several minutes)..."
    
    # Build with no cache to ensure fresh installation
    if docker compose -f docker-compose.solution-automater-sandbox.yml build --no-cache; then
        log_success "Images built successfully"
    else
        log_error "Image build failed"
        exit 1
    fi
}

perform_initial_validation() {
    log_section "Performing Initial Validation ${SHIELD}"
    
    cd "$INSTALL_DIR"
    
    log_info "Validating Docker Compose configuration..."
    if docker compose -f docker-compose.solution-automater-sandbox.yml config >/dev/null; then
        log_success "Docker Compose configuration is valid"
    else
        log_error "Docker Compose configuration is invalid"
        exit 1
    fi
    
    log_info "Validating environment file..."
    if [ -f ".env.solution-automater-sandbox" ]; then
        log_success "Environment file exists"
    else
        log_error "Environment file missing"
        exit 1
    fi
    
    log_info "Testing CLI installation..."
    if command -v sas >/dev/null 2>&1; then
        local sas_version=$(sas version | grep "Version:" | cut -d' ' -f2)
        log_success "SAS CLI working (version: $sas_version)"
    else
        log_error "SAS CLI not accessible"
        log_info "Try: source ~/.bashrc or restart your terminal"
    fi
}

# =============================================================================
# POST-INSTALLATION SETUP
# =============================================================================
create_desktop_shortcut() {
    log_info "Creating desktop shortcuts..."
    
    case "$OS" in
        "Linux")
            local desktop_file="$HOME/Desktop/Solution-Automater-Sandbox.desktop"
            cat > "$desktop_file" << EOF
[Desktop Entry]
Name=Solution-Automater-Sandbox
Comment=Enterprise AI Agent Orchestration Platform
Exec=$HOME/.local/bin/sas start
Icon=$INSTALL_DIR/assets/logo.png
Terminal=true
Type=Application
Categories=Development;
EOF
            chmod +x "$desktop_file"
            log_success "Linux desktop shortcut created"
            ;;
        "macOS")
            log_info "macOS: Use Spotlight to search for 'sas' command"
            ;;
        "Windows")
            log_info "Windows: SAS command available in terminal"
            ;;
    esac
}

setup_autostart() {
    log_info "Setting up auto-start options..."
    
    case "$OS" in
        "Linux")
            if command -v systemctl >/dev/null 2>&1; then
                local service_file="$HOME/.config/systemd/user/solution-automater-sandbox.service"
                mkdir -p "$(dirname "$service_file")"
                
                cat > "$service_file" << EOF
[Unit]
Description=Solution-Automater-Sandbox
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=$HOME/.local/bin/sas start
ExecStop=$HOME/.local/bin/sas stop
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
                
                log_info "Systemd service created. Enable with:"
                echo "  systemctl --user enable solution-automater-sandbox"
                echo "  systemctl --user start solution-automater-sandbox"
            fi
            ;;
        "macOS")
            local plist_file="$HOME/Library/LaunchAgents/com.solution-automater-sandbox.plist"
            cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.solution-automater-sandbox</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HOME/.local/bin/sas</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF
            log_info "LaunchAgent created. Enable with:"
            echo "  launchctl load $plist_file"
            ;;
    esac
}

# =============================================================================
# FINAL CONFIGURATION AND TESTING
# =============================================================================
run_initial_test() {
    log_section "Running Initial Test ${ROCKET}"
    
    log_info "Starting services for initial test..."
    cd "$INSTALL_DIR"
    
    # Start core services only for testing
    if timeout 300 sas start claude-sandbox 2>/dev/null; then
        log_success "Services started successfully"
        
        # Wait for services to be ready
        local retries=0
        local max_retries=30
        
        while [ $retries -lt $max_retries ]; do
            if curl -s http://localhost:8080/health >/dev/null 2>&1; then
                log_success "Health check passed"
                break
            fi
            
            retries=$((retries + 1))
            log_info "Waiting for services to be ready (attempt $retries/$max_retries)..."
            sleep 5
        done
        
        # Stop test services
        sas stop claude-sandbox 2>/dev/null || true
        
        if [ $retries -lt $max_retries ]; then
            log_success "Initial test completed successfully"
            return 0
        else
            log_error "Services did not become ready within timeout"
            return 1
        fi
    else
        log_error "Failed to start services"
        return 1
    fi
}

show_final_instructions() {
    log_section "Installation Complete! ${SUCCESS}"
    
    cat << EOF
${GREEN}${SPARKLES} Solution-Automater-Sandbox has been successfully installed! ${SPARKLES}${NC}

${CYAN}Quick Start:${NC}
  1. ${YELLOW}sas start${NC}                    # Start all services
  2. Open ${YELLOW}https://localhost${NC}      # Access main interface
  3. Open ${YELLOW}https://localhost/grafana${NC} # Access monitoring

${CYAN}Access Points:${NC}
  • ${GREEN}Main Interface:${NC}       https://localhost
  • ${GREEN}Monitoring Dashboard:${NC}  https://localhost/grafana
  • ${GREEN}Orchestrator API:${NC}      https://localhost/orchestrator

${CYAN}Generated Credentials:${NC}
  • ${GREEN}Configuration file:${NC}     $INSTALL_DIR/.env.solution-automater-sandbox
  • ${GREEN}Grafana password:${NC}       See configuration file

${CYAN}Common Commands:${NC}
  • ${YELLOW}sas start${NC}              # Start all services
  • ${YELLOW}sas stop${NC}               # Stop all services  
  • ${YELLOW}sas status${NC}             # Check system status
  • ${YELLOW}sas agent start${NC}        # Start an AI agent
  • ${YELLOW}sas db connect mysql${NC}    # Connect to database safely
  • ${YELLOW}sas security scan${NC}      # Run security scan
  • ${YELLOW}sas monitor${NC}            # Real-time monitoring
  • ${YELLOW}sas help${NC}               # Show all commands

${CYAN}Next Steps:${NC}
  1. ${GREEN}Review configuration:${NC}  $INSTALL_DIR/.env.solution-automater-sandbox
  2. ${GREEN}Add API keys:${NC}          Edit the .env file with your API keys
  3. ${GREEN}Start services:${NC}        Run '${YELLOW}sas start${NC}' to begin

${CYAN}Documentation:${NC}
  • ${GREEN}Installation directory:${NC} $INSTALL_DIR
  • ${GREEN}Configuration directory:${NC} $SAS_HOME
  • ${GREEN}Logs directory:${NC}         $SAS_HOME/logs

${PURPLE}Welcome to the future of AI agent orchestration! ${ROCKET}${NC}

EOF

    # Show platform-specific notes
    case "$OS" in
        "Linux")
            echo -e "${CYAN}Linux-specific notes:${NC}"
            echo "  • Desktop shortcut created on Desktop"
            echo "  • Auto-start service available (see systemctl commands above)"
            ;;
        "macOS")
            echo -e "${CYAN}macOS-specific notes:${NC}"  
            echo "  • Use Spotlight to search for 'sas' command"
            echo "  • LaunchAgent created for auto-start (see launchctl commands above)"
            ;;
        "Windows")
            echo -e "${CYAN}Windows-specific notes:${NC}"
            echo "  • SAS command available in PowerShell/Command Prompt"
            echo "  • Restart terminal if 'sas' command not found"
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Installation completed at: $(date)${NC}"
    echo -e "${CYAN}For support: https://github.com/solution-automater-sandbox/claude-docker${NC}"
}

# =============================================================================
# MAIN INSTALLATION FLOW
# =============================================================================
main() {
    # Ensure we can handle interruption gracefully
    trap 'echo -e "\n${RED}Installation interrupted${NC}"; exit 1' INT TERM
    
    show_banner
    
    # Prerequisite checks
    check_prerequisites
    check_docker_environment
    check_claude_authentication
    check_git_configuration
    
    # Installation
    create_directory_structure
    clone_repository
    setup_environment_configuration
    install_cli_tool
    setup_shell_integration
    
    # Build and validate
    build_initial_images
    perform_initial_validation
    
    # Post-installation setup
    create_desktop_shortcut
    setup_autostart
    
    # Final test and instructions
    if run_initial_test; then
        show_final_instructions
    else
        log_error "Installation completed but initial test failed"
        echo -e "\n${YELLOW}You may need to:"
        echo "1. Check Docker is running"
        echo "2. Review the environment configuration"
        echo "3. Run 'sas status' to diagnose issues"
        echo -e "\n${CYAN}Configuration file: $INSTALL_DIR/.env.solution-automater-sandbox${NC}"
    fi
}

# Handle script being called with specific arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "uninstall")
        log_section "Uninstalling Solution-Automater-Sandbox"
        
        # Stop services
        if command -v sas >/dev/null 2>&1; then
            sas stop 2>/dev/null || true
        fi
        
        # Remove directories
        log_info "Removing installation directories..."
        rm -rf "$INSTALL_DIR" "$SAS_HOME"
        
        # Remove CLI
        sudo rm -f "/usr/local/bin/sas" 2>/dev/null || true
        rm -f "$HOME/.local/bin/sas" 2>/dev/null || true
        
        # Remove Docker images
        log_info "Removing Docker images..."
        docker images | grep -E "solution-automater-sandbox|sas-" | awk '{print $3}' | xargs -r docker rmi -f 2>/dev/null || true
        
        log_success "Solution-Automater-Sandbox uninstalled"
        ;;
    "help"|"--help"|"-h")
        echo "Solution-Automater-Sandbox Installer"
        echo ""
        echo "Usage: $0 [install|uninstall|help]"
        echo ""
        echo "Commands:"
        echo "  install     - Install Solution-Automater-Sandbox (default)"
        echo "  uninstall   - Remove Solution-Automater-Sandbox completely"
        echo "  help        - Show this help message"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac