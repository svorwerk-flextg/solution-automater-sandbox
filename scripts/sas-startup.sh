#!/bin/bash

# =============================================================================
# SOLUTION-AUTOMATER-SANDBOX STARTUP SCRIPT
# Enhanced startup with monitoring, health checks, and orchestration
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION AND ENVIRONMENT
# =============================================================================
SAS_HOME="${SAS_HOME:-/home/sas-user}"
SAS_CONFIG_DIR="${SAS_CONFIG_DIR:-/app/configs}"
SAS_LOGS_DIR="${SAS_LOGS_DIR:-/var/log/sas}"
SAS_MODE="${SAS_MODE:-production}"
AGENT_ID="${AGENT_ID:-$(hostname)-$(date +%s)}"
SESSION_ID="${SESSION_ID:-$(uuidgen 2>/dev/null || echo "session-$(date +%s)")}"

# Logging configuration
LOG_FILE="${SAS_LOGS_DIR}/startup.log"
mkdir -p "$(dirname "$LOG_FILE")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case "$level" in
        "ERROR")
            echo -e "${RED}❌ $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "DEBUG")
            if [ "${SAS_DEBUG:-false}" = "true" ]; then
                echo -e "${PURPLE}🔍 $message${NC}"
            fi
            ;;
    esac
}

log_error() { log "ERROR" "$1"; }
log_warn() { log "WARN" "$1"; }
log_info() { log "INFO" "$1"; }
log_success() { log "SUCCESS" "$1"; }
log_debug() { log "DEBUG" "$1"; }

# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================
check_system_health() {
    log_info "Performing system health checks..."
    
    # Check disk space
    local disk_usage=$(df /workspace | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        log_warn "Disk usage is high: ${disk_usage}%"
    else
        log_debug "Disk usage: ${disk_usage}%"
    fi
    
    # Check memory usage
    local mem_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    log_debug "Memory usage: ${mem_usage}%"
    
    # Check if running in container
    if [ -f /.dockerenv ]; then
        log_debug "Running in Docker container"
        
        # Check Docker socket availability if needed
        if [ -S /var/run/docker.sock ]; then
            log_debug "Docker socket available"
        fi
    fi
    
    # Check network connectivity
    if ping -c 1 google.com >/dev/null 2>&1; then
        log_debug "Network connectivity: OK"
    else
        log_warn "Network connectivity issues detected"
    fi
    
    log_success "System health checks completed"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check Node.js and Claude Code
    if ! command -v claude >/dev/null 2>&1; then
        missing_deps+=("claude-code")
    fi
    
    # Check Python
    if ! command -v python3 >/dev/null 2>&1; then
        missing_deps+=("python3")
    fi
    
    # Check Git
    if ! command -v git >/dev/null 2>&1; then
        missing_deps+=("git")
    fi
    
    # Check uv
    if ! command -v uv >/dev/null 2>&1; then
        log_warn "uv package manager not found - some MCP servers may not work"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    log_success "All dependencies available"
}

check_authentication() {
    log_info "Checking Claude authentication..."
    
    if [ -f "$SAS_HOME/.claude.json" ]; then
        log_success "Claude authentication found"
        
        # Validate authentication by checking file content
        if [ -s "$SAS_HOME/.claude.json" ]; then
            log_debug "Authentication file is not empty"
        else
            log_warn "Authentication file is empty"
        fi
    else
        log_error "Claude authentication not found at $SAS_HOME/.claude.json"
        log_error "Please run 'claude' command on host to authenticate first"
        exit 1
    fi
}

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================
setup_environment() {
    log_info "Setting up Solution-Automater-Sandbox environment..."
    
    # Create necessary directories
    mkdir -p "$SAS_LOGS_DIR" "$SAS_HOME/.cache" "$SAS_HOME/.config"
    
    # Set up PATH extensions
    export PATH="$SAS_HOME/scripts:$SAS_HOME/.local/bin:$PATH"
    export PYTHONPATH="$SAS_HOME/scripts:/app:/app/cloud_integration:/app/orchestration:${PYTHONPATH:-}"
    
    # SAS-specific environment variables
    export SAS_AGENT_ID="$AGENT_ID"
    export SAS_SESSION_ID="$SESSION_ID"
    export SAS_STARTUP_TIME="$(date -Iseconds)"
    export SAS_LOG_LEVEL="${SAS_LOG_LEVEL:-INFO}"
    
    # Configure Git safe directory
    git config --global --add safe.directory /workspace 2>/dev/null || true
    
    log_success "Environment setup completed"
}

setup_monitoring() {
    log_info "Setting up monitoring and observability..."
    
    # Start background health monitoring if enabled
    if [ "${MONITORING_ENABLED:-true}" = "true" ]; then
        {
            while true; do
                sleep 300  # Check every 5 minutes
                
                # Check system resources
                local load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
                local mem_percent=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
                
                log_debug "Health check - Load: $load_avg, Memory: ${mem_percent}%"
                
                # Log to monitoring file
                echo "$(date -Iseconds),load,$load_avg" >> "$SAS_LOGS_DIR/metrics.log"
                echo "$(date -Iseconds),memory,$mem_percent" >> "$SAS_LOGS_DIR/metrics.log"
            done
        } &
        
        local monitor_pid=$!
        echo "$monitor_pid" > "$SAS_LOGS_DIR/monitor.pid"
        log_debug "Background monitoring started (PID: $monitor_pid)"
    fi
}

configure_mcp_servers() {
    log_info "Configuring MCP servers..."
    
    # Copy MCP configuration if it doesn't exist
    if [ ! -f "$SAS_HOME/.claude/settings.json" ] && [ -f "/app/.claude/settings.json" ]; then
        log_info "Copying default MCP configuration..."
        cp "/app/.claude/settings.json" "$SAS_HOME/.claude/settings.json"
    fi
    
    # Validate MCP configuration
    if [ -f "$SAS_HOME/.claude/settings.json" ]; then
        if python3 -c "import json; json.load(open('$SAS_HOME/.claude/settings.json'))" 2>/dev/null; then
            log_success "MCP configuration is valid"
        else
            log_error "MCP configuration is invalid JSON"
            exit 1
        fi
    else
        log_warn "No MCP configuration found"
    fi
}

# =============================================================================
# AGENT MODE CONFIGURATION
# =============================================================================
configure_agent_mode() {
    case "$SAS_MODE" in
        "main")
            log_info "Configuring main Claude agent..."
            setup_main_agent
            ;;
        "worker")
            log_info "Configuring worker agent..."
            setup_worker_agent
            ;;
        "development")
            log_info "Configuring development mode..."
            setup_development_mode
            ;;
        *)
            log_info "Using default production configuration..."
            setup_main_agent
            ;;
    esac
}

setup_main_agent() {
    log_debug "Setting up main agent configuration"
    
    # Enable all features for main agent
    export CLAUDE_FEATURES="full"
    export CLAUDE_PERMISSIONS="--dangerously-skip-permissions"
    export CLAUDE_PORT="8080"
    
    # Setup workspace
    cd /workspace
    
    log_success "Main agent configured"
}

setup_worker_agent() {
    log_debug "Setting up worker agent configuration"
    
    # Restricted features for worker agents
    export CLAUDE_FEATURES="worker"
    export CLAUDE_PERMISSIONS=""
    export CLAUDE_PORT="8081"
    
    # Use temporary workspace
    local worker_workspace="/tmp/sas-worker-$AGENT_ID"
    mkdir -p "$worker_workspace"
    cd "$worker_workspace"
    
    log_success "Worker agent configured"
}

setup_development_mode() {
    log_debug "Setting up development mode"
    
    # Development-friendly settings
    export CLAUDE_FEATURES="full"
    export CLAUDE_PERMISSIONS="--dangerously-skip-permissions"
    export CLAUDE_PORT="8080"
    export SAS_DEBUG="true"
    export SAS_LOG_LEVEL="DEBUG"
    
    cd /workspace
    
    log_success "Development mode configured"
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
setup_security() {
    if [ "${SECURITY_ENABLED:-true}" = "true" ]; then
        log_info "Configuring security settings..."
        
        # Set secure file permissions
        chmod 700 "$SAS_HOME"
        chmod 600 "$SAS_HOME/.claude.json" 2>/dev/null || true
        
        # Configure SSH if directory exists
        if [ -d "$SAS_HOME/.ssh" ]; then
            chmod 700 "$SAS_HOME/.ssh"
            find "$SAS_HOME/.ssh" -type f -name "*_rsa" -exec chmod 600 {} \;
            find "$SAS_HOME/.ssh" -type f -name "*_rsa.pub" -exec chmod 644 {} \;
        fi
        
        # Set up security monitoring
        if command -v iptables >/dev/null 2>&1; then
            log_debug "Security monitoring available"
        fi
        
        log_success "Security configuration completed"
    else
        log_debug "Security configuration skipped"
    fi
}

# =============================================================================
# CLOUD INTEGRATION SETUP
# =============================================================================
setup_cloud_integrations() {
    log_info "Setting up cloud integrations..."
    
    # Check for Fabric configuration
    if [ -n "${FABRIC_WORKSPACE_ID:-}" ]; then
        log_debug "Microsoft Fabric integration enabled"
        export FABRIC_ENABLED="true"
    fi
    
    # Check for AWS configuration
    if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
        log_debug "AWS integration enabled"
        export AWS_ENABLED="true"
    fi
    
    # Initialize cloud connectors
    if [ -f "/app/cloud_integration/init.py" ]; then
        python3 /app/cloud_integration/init.py --validate 2>/dev/null || log_warn "Cloud integration validation failed"
    fi
    
    log_success "Cloud integrations configured"
}

# =============================================================================
# STARTUP COORDINATION
# =============================================================================
wait_for_dependencies() {
    log_info "Waiting for dependent services..."
    
    local services=("sas-redis:6379" "sas-vault:8200")
    
    for service in "${services[@]}"; do
        local host_port=(${service//:/ })
        local host="${host_port[0]}"
        local port="${host_port[1]}"
        
        log_debug "Checking $host:$port..."
        
        local retries=0
        local max_retries=30
        
        while ! nc -z "$host" "$port" 2>/dev/null; do
            if [ $retries -ge $max_retries ]; then
                log_warn "Service $service not available after ${max_retries} retries"
                break
            fi
            
            retries=$((retries + 1))
            log_debug "Waiting for $service (attempt $retries/$max_retries)..."
            sleep 2
        done
        
        if nc -z "$host" "$port" 2>/dev/null; then
            log_success "Service $service is available"
        fi
    done
}

register_agent() {
    log_info "Registering agent with orchestrator..."
    
    # Register with orchestrator if available
    if nc -z localhost 8090 2>/dev/null; then
        local registration_data=$(cat << EOF
{
  "agent_id": "$AGENT_ID",
  "session_id": "$SESSION_ID",
  "mode": "$SAS_MODE",
  "capabilities": ["claude-code", "mcp-servers", "file-operations"],
  "startup_time": "$SAS_STARTUP_TIME",
  "health_endpoint": "http://localhost:${CLAUDE_PORT:-8080}/health"
}
EOF
)
        
        if curl -s -X POST http://localhost:8090/agents/register \
            -H "Content-Type: application/json" \
            -d "$registration_data" >/dev/null 2>&1; then
            log_success "Agent registered with orchestrator"
        else
            log_warn "Failed to register with orchestrator"
        fi
    else
        log_debug "Orchestrator not available - running standalone"
    fi
}

# =============================================================================
# HEALTH CHECK ENDPOINT
# =============================================================================
setup_health_endpoint() {
    log_info "Setting up health check endpoint..."
    
    # Create simple HTTP health check server
    cat > /tmp/health_server.py << 'EOF'
#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import psutil
from datetime import datetime

class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            health_data = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "agent_id": os.environ.get('SAS_AGENT_ID', 'unknown'),
                "session_id": os.environ.get('SAS_SESSION_ID', 'unknown'),
                "mode": os.environ.get('SAS_MODE', 'unknown'),
                "uptime": self.get_uptime(),
                "system": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent
                }
            }
            
            self.wfile.write(json.dumps(health_data, indent=2).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_uptime(self):
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
            return f"{uptime_seconds:.1f}s"
        except:
            return "unknown"

if __name__ == "__main__":
    PORT = int(os.environ.get('HEALTH_PORT', '8888'))
    Handler = HealthHandler
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Health server running on port {PORT}")
        httpd.serve_forever()
EOF
    
    chmod +x /tmp/health_server.py
    
    # Start health server in background
    python3 /tmp/health_server.py &
    local health_pid=$!
    echo "$health_pid" > "$SAS_LOGS_DIR/health.pid"
    log_debug "Health server started (PID: $health_pid)"
}

# =============================================================================
# CLAUDE CODE STARTUP
# =============================================================================
start_claude_code() {
    log_info "Starting Claude Code..."
    
    # Configure Claude Code options
    local claude_options=("--dangerously-skip-permissions")
    
    if [ "${SAS_MODE}" = "worker" ]; then
        claude_options+=("--no-browser")
    fi
    
    # Add port if specified
    if [ -n "${CLAUDE_PORT:-}" ]; then
        claude_options+=("--port" "$CLAUDE_PORT")
    fi
    
    # Set working directory based on mode
    local work_dir="/workspace"
    if [ "${SAS_MODE}" = "worker" ]; then
        work_dir="/tmp/sas-worker-$AGENT_ID"
    fi
    
    cd "$work_dir"
    
    log_info "Starting Claude Code in $work_dir with options: ${claude_options[*]}"
    
    # Start Claude Code
    exec claude "${claude_options[@]}"
}

# =============================================================================
# CLEANUP AND SIGNAL HANDLING
# =============================================================================
cleanup() {
    log_info "Shutting down Solution-Automater-Sandbox..."
    
    # Stop health server
    if [ -f "$SAS_LOGS_DIR/health.pid" ]; then
        local health_pid=$(cat "$SAS_LOGS_DIR/health.pid")
        kill "$health_pid" 2>/dev/null || true
        rm -f "$SAS_LOGS_DIR/health.pid"
        log_debug "Health server stopped"
    fi
    
    # Stop monitoring
    if [ -f "$SAS_LOGS_DIR/monitor.pid" ]; then
        local monitor_pid=$(cat "$SAS_LOGS_DIR/monitor.pid")
        kill "$monitor_pid" 2>/dev/null || true
        rm -f "$SAS_LOGS_DIR/monitor.pid"
        log_debug "Monitoring stopped"
    fi
    
    # Unregister agent
    if nc -z localhost 8090 2>/dev/null; then
        curl -s -X DELETE "http://localhost:8090/agents/$AGENT_ID" >/dev/null 2>&1 || true
        log_debug "Agent unregistered from orchestrator"
    fi
    
    log_success "Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

# =============================================================================
# MAIN STARTUP SEQUENCE
# =============================================================================
main() {
    echo -e "\n${PURPLE}🚀 Solution-Automater-Sandbox Starting...${NC}\n"
    
    # Core system checks
    check_system_health
    check_dependencies
    check_authentication
    
    # Environment setup
    setup_environment
    setup_security
    setup_monitoring
    
    # Service configuration
    configure_mcp_servers
    configure_agent_mode
    setup_cloud_integrations
    
    # Startup coordination
    wait_for_dependencies
    register_agent
    setup_health_endpoint
    
    log_success "Solution-Automater-Sandbox startup completed"
    log_info "Agent ID: $AGENT_ID"
    log_info "Session ID: $SESSION_ID"
    log_info "Mode: $SAS_MODE"
    log_info "Log file: $LOG_FILE"
    
    # Start Claude Code (this will take over as the main process)
    start_claude_code
}

# Handle script being called directly vs sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi