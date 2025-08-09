#!/bin/bash

# =============================================================================
# SOLUTION-AUTOMATER-SANDBOX ENHANCED MCP SERVERS INSTALLER
# Production-grade MCP server installation with monitoring and validation
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
MCP_SERVERS_FILE="${MCP_SERVERS_FILE:-/app/mcp-servers.txt}"
MCP_LOG_FILE="${SAS_LOGS_DIR:-/var/log/sas}/mcp-installation.log"
MCP_CONFIG_DIR="${SAS_CONFIG_DIR:-/app/configs}/mcp"
CLAUDE_CONFIG_FILE="${HOME}/.claude/settings.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

SUCCESS="✅"
ERROR="❌"
WARNING="⚠️"
INFO="ℹ️"
GEAR="⚙️"

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$MCP_LOG_FILE"
    
    case "$level" in
        "ERROR")
            echo -e "${RED}${ERROR} $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}${WARNING} $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}${INFO} $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}${SUCCESS} $message${NC}"
            ;;
    esac
}

log_info() { log "INFO" "$1"; }
log_success() { log "SUCCESS" "$1"; }
log_warn() { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
check_prerequisites() {
    log_info "Checking MCP server prerequisites..."
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$MCP_LOG_FILE")"
    mkdir -p "$MCP_CONFIG_DIR"
    
    # Check for required tools
    local missing_tools=()
    
    local required_tools=("curl" "python3" "pip" "npm" "node")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        return 1
    fi
    
    # Check for uv (preferred Python package manager)
    if command -v uv >/dev/null 2>&1; then
        log_success "UV package manager available"
        export USE_UV=true
    else
        log_warn "UV not available, falling back to pip"
        export USE_UV=false
    fi
    
    log_success "Prerequisites check completed"
}

validate_mcp_servers_file() {
    if [ ! -f "$MCP_SERVERS_FILE" ]; then
        log_error "MCP servers file not found: $MCP_SERVERS_FILE"
        return 1
    fi
    
    if [ ! -s "$MCP_SERVERS_FILE" ]; then
        log_error "MCP servers file is empty: $MCP_SERVERS_FILE"
        return 1
    fi
    
    log_success "MCP servers file validated"
}

# =============================================================================
# MCP SERVER INSTALLATION FUNCTIONS
# =============================================================================
install_python_mcp_server() {
    local server_spec="$1"
    local server_name="$2"
    
    log_info "Installing Python MCP server: $server_name"
    
    if [ "$USE_UV" = "true" ]; then
        if uv pip install "$server_spec"; then
            log_success "Installed $server_name via UV"
            return 0
        else
            log_warn "UV installation failed for $server_name, trying pip..."
        fi
    fi
    
    if pip install --user "$server_spec"; then
        log_success "Installed $server_name via pip"
        return 0
    else
        log_error "Failed to install $server_name"
        return 1
    fi
}

install_npm_mcp_server() {
    local server_spec="$1"
    local server_name="$2"
    
    log_info "Installing NPM MCP server: $server_name"
    
    if npm install -g "$server_spec"; then
        log_success "Installed $server_name via npm"
        return 0
    else
        log_error "Failed to install $server_name"
        return 1
    fi
}

install_git_mcp_server() {
    local repo_url="$1"
    local server_name="$2"
    local install_path="/tmp/mcp-$server_name-$(date +%s)"
    
    log_info "Installing Git MCP server: $server_name from $repo_url"
    
    if git clone "$repo_url" "$install_path"; then
        cd "$install_path"
        
        # Try different installation methods
        if [ -f "setup.py" ]; then
            if python3 setup.py install --user; then
                log_success "Installed $server_name via setup.py"
                cd - && rm -rf "$install_path"
                return 0
            fi
        elif [ -f "pyproject.toml" ]; then
            if pip install --user .; then
                log_success "Installed $server_name via pyproject.toml"
                cd - && rm -rf "$install_path"
                return 0
            fi
        elif [ -f "package.json" ]; then
            if npm install -g .; then
                log_success "Installed $server_name via package.json"
                cd - && rm -rf "$install_path"
                return 0
            fi
        fi
        
        cd - && rm -rf "$install_path"
    fi
    
    log_error "Failed to install $server_name from git"
    return 1
}

# =============================================================================
# CONFIGURATION GENERATION
# =============================================================================
generate_claude_config() {
    log_info "Generating Claude Code MCP configuration..."
    
    # Backup existing configuration
    if [ -f "$CLAUDE_CONFIG_FILE" ]; then
        cp "$CLAUDE_CONFIG_FILE" "$CLAUDE_CONFIG_FILE.backup.$(date +%s)"
        log_info "Backed up existing Claude configuration"
    fi
    
    # Create configuration directory
    mkdir -p "$(dirname "$CLAUDE_CONFIG_FILE")"
    
    # Generate configuration
    cat > "$CLAUDE_CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "serena": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp-server-serena",
        "mcp-server-serena"
      ]
    },
    "context7": {
      "command": "npx",
      "args": [
        "-y",
        "@context7/mcp-server"
      ]
    },
    "twilio": {
      "command": "python",
      "args": [
        "-m",
        "sms_mcp_server"
      ],
      "env": {
        "TWILIO_ACCOUNT_SID": "${TWILIO_ACCOUNT_SID}",
        "TWILIO_AUTH_TOKEN": "${TWILIO_AUTH_TOKEN}",
        "TWILIO_PHONE_NUMBER": "${TWILIO_FROM_NUMBER}",
        "TWILIO_RECIPIENT_NUMBER": "${TWILIO_TO_NUMBER}"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/workspace"
      ]
    },
    "desktop-commander": {
      "command": "npx",
      "args": [
        "-y",
        "desktop-commander-mcp"
      ]
    },
    "playwright": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-playwright"
      ]
    },
    "aws-docs": {
      "command": "python",
      "args": [
        "-m",
        "aws_documentation_mcp_server"
      ]
    },
    "aws-cdk-docs": {
      "command": "python",
      "args": [
        "-m",
        "aws_cdk_documentation_mcp_server"
      ]
    },
    "magic": {
      "command": "npx",
      "args": [
        "-y",
        "@21st-digital/mcp-server-magic"
      ]
    },
    "sequential-thinking": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-sequential-thinking"
      ]
    }
  }
}
EOF
    
    log_success "Claude configuration generated"
}

validate_mcp_installation() {
    log_info "Validating MCP server installations..."
    
    local validation_errors=0
    
    # Test Python MCP servers
    local python_servers=("sms_mcp_server" "aws_documentation_mcp_server" "aws_cdk_documentation_mcp_server")
    
    for server in "${python_servers[@]}"; do
        if python3 -c "import $server" 2>/dev/null; then
            log_success "Python MCP server validated: $server"
        else
            log_error "Python MCP server validation failed: $server"
            validation_errors=$((validation_errors + 1))
        fi
    done
    
    # Test NPM MCP servers
    local npm_servers=("@context7/mcp-server" "@modelcontextprotocol/server-filesystem" "@modelcontextprotocol/server-playwright")
    
    for server in "${npm_servers[@]}"; do
        if npm list -g "$server" >/dev/null 2>&1; then
            log_success "NPM MCP server validated: $server"
        else
            log_warn "NPM MCP server validation failed: $server (may be installed locally)"
        fi
    done
    
    # Test UV-based servers
    if [ "$USE_UV" = "true" ]; then
        if uv pip list | grep -q "mcp-server-serena"; then
            log_success "UV MCP server validated: mcp-server-serena"
        else
            log_error "UV MCP server validation failed: mcp-server-serena"
            validation_errors=$((validation_errors + 1))
        fi
    fi
    
    if [ $validation_errors -eq 0 ]; then
        log_success "All MCP servers validated successfully"
        return 0
    else
        log_warn "$validation_errors MCP server(s) failed validation"
        return 1
    fi
}

# =============================================================================
# ENHANCED MCP SERVERS INSTALLATION
# =============================================================================
install_enhanced_mcp_servers() {
    log_info "Installing enhanced MCP servers for Solution-Automater-Sandbox..."
    
    local installation_errors=0
    
    # Core MCP Servers (Essential)
    log_info "Installing core MCP servers..."
    
    # Serena (Advanced coding toolkit)
    if [ "$USE_UV" = "true" ]; then
        if ! uv pip install mcp-server-serena; then
            log_error "Failed to install Serena MCP server"
            installation_errors=$((installation_errors + 1))
        fi
    else
        if ! pip install --user mcp-server-serena; then
            log_error "Failed to install Serena MCP server"
            installation_errors=$((installation_errors + 1))
        fi
    fi
    
    # Context7 (Documentation integration)
    if ! npm install -g @context7/mcp-server; then
        log_error "Failed to install Context7 MCP server"
        installation_errors=$((installation_errors + 1))
    fi
    
    # Twilio (SMS notifications)
    if ! pip install --user sms-mcp-server; then
        log_error "Failed to install Twilio MCP server"
        installation_errors=$((installation_errors + 1))
    fi
    
    # Standard MCP Servers
    log_info "Installing standard MCP servers..."
    
    local standard_servers=(
        "@modelcontextprotocol/server-filesystem"
        "@modelcontextprotocol/server-playwright"
        "@modelcontextprotocol/server-sequential-thinking"
        "@21st-digital/mcp-server-magic"
        "desktop-commander-mcp"
    )
    
    for server in "${standard_servers[@]}"; do
        if ! npm install -g "$server"; then
            log_error "Failed to install $server"
            installation_errors=$((installation_errors + 1))
        fi
    done
    
    # AWS Documentation MCP Servers
    log_info "Installing AWS documentation MCP servers..."
    
    local aws_servers=(
        "aws-documentation-mcp-server"
        "aws-cdk-documentation-mcp-server"
    )
    
    for server in "${aws_servers[@]}"; do
        if ! pip install --user "$server"; then
            log_error "Failed to install $server"
            installation_errors=$((installation_errors + 1))
        fi
    done
    
    # Additional Enterprise MCP Servers
    log_info "Installing additional enterprise MCP servers..."
    
    # GitHub integration
    if ! npm install -g @modelcontextprotocol/server-github; then
        log_warn "Failed to install GitHub MCP server (optional)"
    fi
    
    # Database integration
    if ! pip install --user mcp-server-database; then
        log_warn "Failed to install Database MCP server (optional)"
    fi
    
    # Monitoring integration
    if ! pip install --user mcp-server-prometheus; then
        log_warn "Failed to install Prometheus MCP server (optional)"
    fi
    
    log_info "MCP servers installation completed with $installation_errors errors"
    return $installation_errors
}

create_mcp_health_monitor() {
    log_info "Creating MCP health monitoring script..."
    
    cat > "${MCP_CONFIG_DIR}/health-monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
MCP Servers Health Monitor
Monitors the health and availability of installed MCP servers
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

def check_python_mcp_server(module_name: str) -> Dict[str, Any]:
    """Check if a Python MCP server module is available"""
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}; print('OK')"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "status": "healthy" if result.returncode == 0 else "unhealthy",
            "module": module_name,
            "error": result.stderr if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "module": module_name, "error": "Import timeout"}
    except Exception as e:
        return {"status": "error", "module": module_name, "error": str(e)}

def check_npm_mcp_server(package_name: str) -> Dict[str, Any]:
    """Check if an NPM MCP server package is available"""
    try:
        result = subprocess.run(
            ["npm", "list", "-g", package_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "status": "healthy" if result.returncode == 0 else "unhealthy",
            "package": package_name,
            "error": result.stderr if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "package": package_name, "error": "Check timeout"}
    except Exception as e:
        return {"status": "error", "package": package_name, "error": str(e)}

def main():
    print("Checking MCP servers health...")
    
    # Python MCP servers
    python_servers = [
        "sms_mcp_server",
        "aws_documentation_mcp_server", 
        "aws_cdk_documentation_mcp_server"
    ]
    
    # NPM MCP servers
    npm_servers = [
        "@context7/mcp-server",
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-playwright",
        "@21st-digital/mcp-server-magic"
    ]
    
    results = {
        "timestamp": time.time(),
        "python_servers": {},
        "npm_servers": {},
        "summary": {"total": 0, "healthy": 0, "unhealthy": 0, "errors": 0}
    }
    
    # Check Python servers
    for server in python_servers:
        result = check_python_mcp_server(server)
        results["python_servers"][server] = result
        results["summary"]["total"] += 1
        
        if result["status"] == "healthy":
            results["summary"]["healthy"] += 1
        elif result["status"] == "unhealthy":
            results["summary"]["unhealthy"] += 1
        else:
            results["summary"]["errors"] += 1
    
    # Check NPM servers  
    for server in npm_servers:
        result = check_npm_mcp_server(server)
        results["npm_servers"][server] = result
        results["summary"]["total"] += 1
        
        if result["status"] == "healthy":
            results["summary"]["healthy"] += 1
        elif result["status"] == "unhealthy":
            results["summary"]["unhealthy"] += 1
        else:
            results["summary"]["errors"] += 1
    
    # Output results
    print(json.dumps(results, indent=2))
    
    # Exit with error code if any servers are unhealthy
    if results["summary"]["unhealthy"] > 0 or results["summary"]["errors"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "${MCP_CONFIG_DIR}/health-monitor.py"
    log_success "MCP health monitor created"
}

# =============================================================================
# MAIN INSTALLATION PROCESS
# =============================================================================
main() {
    echo -e "\n${PURPLE}${GEAR} Installing Solution-Automater-Sandbox MCP Servers...${NC}\n"
    
    # Prerequisites and validation
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    # Install enhanced MCP servers
    local install_errors
    install_errors=$(install_enhanced_mcp_servers)
    
    # Generate configuration
    generate_claude_config
    
    # Create health monitoring
    create_mcp_health_monitor
    
    # Validate installation
    if validate_mcp_installation; then
        log_success "MCP server validation passed"
    else
        log_warn "Some MCP servers failed validation"
    fi
    
    # Generate installation report
    local report_file="${MCP_CONFIG_DIR}/installation-report.json"
    cat > "$report_file" << EOF
{
  "installation_date": "$(date -Iseconds)",
  "sas_version": "${SAS_VERSION:-1.0.0}",
  "install_errors": $install_errors,
  "config_file": "$CLAUDE_CONFIG_FILE",
  "log_file": "$MCP_LOG_FILE",
  "health_monitor": "${MCP_CONFIG_DIR}/health-monitor.py"
}
EOF
    
    echo -e "\n${GREEN}${SUCCESS} MCP Servers Installation Completed${NC}"
    echo -e "${BLUE}${INFO} Installation report: $report_file${NC}"
    echo -e "${BLUE}${INFO} Log file: $MCP_LOG_FILE${NC}"
    echo -e "${BLUE}${INFO} Health monitor: ${MCP_CONFIG_DIR}/health-monitor.py${NC}"
    
    if [ "$install_errors" -eq 0 ]; then
        echo -e "${GREEN}${SUCCESS} All MCP servers installed successfully${NC}"
        exit 0
    else
        echo -e "${YELLOW}${WARNING} $install_errors error(s) occurred during installation${NC}"
        echo -e "${BLUE}${INFO} Check log file for details: $MCP_LOG_FILE${NC}"
        exit $install_errors
    fi
}

# Handle script being called directly vs sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi