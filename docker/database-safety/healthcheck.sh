#!/bin/bash
set -e

# Database Safety Layer Health Check Script
# Comprehensive health validation for container orchestration

# Configuration
HEALTH_CHECK_TIMEOUT=10
API_HOST=${DB_SAFETY_HOST:-localhost}
API_PORT=${DB_SAFETY_PORT:-8080}
HEALTH_ENDPOINT="http://${API_HOST}:${API_PORT}/health"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[HEALTH] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[HEALTH] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[HEALTH] ERROR: $1${NC}"
}

# Check if process is running
check_process() {
    if pgrep -f "uvicorn.*main:app" > /dev/null; then
        log "✅ API process is running"
        return 0
    else
        error "❌ API process not found"
        return 1
    fi
}

# Check API endpoint
check_api_endpoint() {
    local response
    local http_code
    
    # Use timeout to prevent hanging
    response=$(timeout $HEALTH_CHECK_TIMEOUT curl -s -w "HTTP_CODE:%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "CURL_FAILED")
    
    if [[ "$response" == "CURL_FAILED" ]]; then
        error "❌ Failed to connect to API endpoint"
        return 1
    fi
    
    # Extract HTTP code
    http_code=$(echo "$response" | sed -n 's/.*HTTP_CODE:\([0-9]*\)$/\1/p')
    
    if [[ "$http_code" == "200" ]]; then
        log "✅ API endpoint responding (HTTP $http_code)"
        return 0
    else
        error "❌ API endpoint returned HTTP $http_code"
        return 1
    fi
}

# Check API response content
check_api_response() {
    local response
    local status
    
    response=$(timeout $HEALTH_CHECK_TIMEOUT curl -s "$HEALTH_ENDPOINT" 2>/dev/null || echo '{}')
    
    # Check if response contains expected health status
    status=$(echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('status', 'unknown'))
except:
    print('invalid')
" 2>/dev/null || echo "invalid")
    
    if [[ "$status" == "healthy" ]]; then
        log "✅ API reports healthy status"
        return 0
    else
        error "❌ API reports status: $status"
        return 1
    fi
}

# Check system resources
check_resources() {
    local memory_usage
    local disk_usage
    
    # Check memory usage (percentage)
    memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [[ $memory_usage -lt 90 ]]; then
        log "✅ Memory usage: ${memory_usage}%"
    else
        warn "⚠️  High memory usage: ${memory_usage}%"
    fi
    
    # Check disk usage for /tmp (sandbox storage)
    if mountpoint -q /tmp 2>/dev/null; then
        disk_usage=$(df /tmp | awk 'NR==2{printf "%.0f", $3*100/$2}')
        if [[ $disk_usage -lt 90 ]]; then
            log "✅ Disk usage (/tmp): ${disk_usage}%"
        else
            warn "⚠️  High disk usage (/tmp): ${disk_usage}%"
        fi
    fi
}

# Check configuration file
check_configuration() {
    if [[ -f "$DB_SAFETY_CONFIG" ]]; then
        log "✅ Configuration file exists: $DB_SAFETY_CONFIG"
        return 0
    else
        warn "⚠️  Configuration file not found: $DB_SAFETY_CONFIG"
        return 0  # Non-critical for health check
    fi
}

# Check log directory
check_log_directory() {
    if [[ -d "/var/log/database_safety" ]] && [[ -w "/var/log/database_safety" ]]; then
        log "✅ Log directory is writable"
        return 0
    else
        warn "⚠️  Log directory not writable: /var/log/database_safety"
        return 0  # Non-critical for health check
    fi
}

# Check sandbox storage
check_sandbox_storage() {
    if [[ -d "/tmp/database_sandboxes" ]] && [[ -w "/tmp/database_sandboxes" ]]; then
        log "✅ Sandbox storage is accessible"
        return 0
    else
        warn "⚠️  Sandbox storage not accessible: /tmp/database_sandboxes"
        return 0  # Non-critical for health check
    fi
}

# Check external dependencies (optional)
check_external_dependencies() {
    local deps_healthy=true
    
    # Check Redis if configured
    if [[ -n "$REDIS_HOST" ]] && [[ -n "$REDIS_PORT" ]]; then
        if timeout 3 nc -z "$REDIS_HOST" "$REDIS_PORT" 2>/dev/null; then
            log "✅ Redis connectivity: $REDIS_HOST:$REDIS_PORT"
        else
            warn "⚠️  Redis not accessible: $REDIS_HOST:$REDIS_PORT"
            deps_healthy=false
        fi
    fi
    
    # Note: We don't fail health check for external dependencies
    # as they may be temporarily unavailable
    return 0
}

# Main health check function
main() {
    local exit_code=0
    
    log "Starting health check..."
    
    # Critical checks (will fail health check)
    if ! check_process; then
        exit_code=1
    fi
    
    if ! check_api_endpoint; then
        exit_code=1
    fi
    
    if ! check_api_response; then
        exit_code=1
    fi
    
    # Non-critical checks (warnings only)
    check_configuration
    check_log_directory
    check_sandbox_storage
    check_resources
    check_external_dependencies
    
    if [[ $exit_code -eq 0 ]]; then
        log "🎉 Health check passed"
        echo "healthy"
        exit 0
    else
        error "💥 Health check failed"
        echo "unhealthy"
        exit 1
    fi
}

# Handle timeout
timeout_handler() {
    error "⏰ Health check timed out"
    echo "timeout"
    exit 1
}

# Set up timeout handling
trap timeout_handler ALRM

# Run main function with overall timeout
(
    sleep $HEALTH_CHECK_TIMEOUT
    kill -ALRM $$
) &
timeout_pid=$!

main "$@"
health_exit_code=$?

# Clean up timeout handler
kill $timeout_pid 2>/dev/null
wait $timeout_pid 2>/dev/null

exit $health_exit_code