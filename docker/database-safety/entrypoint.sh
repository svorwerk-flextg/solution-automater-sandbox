#!/bin/bash
set -e

# Database Safety Layer Entrypoint Script
# Handles service initialization and command routing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Wait for service to be available
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local max_attempts=30
    local attempt=1

    log "Waiting for $service_name at $host:$port..."
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z "$host" "$port" 2>/dev/null; then
            log "$service_name is available!"
            return 0
        fi
        
        log "Attempt $attempt/$max_attempts: $service_name not ready, waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    warn "$service_name is not available after $max_attempts attempts, continuing anyway..."
    return 1
}

# Initialize directories
init_directories() {
    log "Initializing directories..."
    
    # Ensure required directories exist
    mkdir -p /var/log/database_safety
    mkdir -p /tmp/database_sandboxes
    mkdir -p /app/data
    mkdir -p /app/backups
    
    # Set permissions
    chmod 755 /var/log/database_safety
    chmod 755 /tmp/database_sandboxes
    
    log "Directories initialized"
}

# Validate configuration
validate_config() {
    log "Validating configuration..."
    
    if [ ! -f "$DB_SAFETY_CONFIG" ]; then
        warn "Configuration file not found: $DB_SAFETY_CONFIG"
        warn "Using environment variable configuration"
        return 0
    fi
    
    # Validate config file with Python
    python3 -c "
import sys
sys.path.insert(0, '/app/database_safety')
from core.config import ConfigManager
import asyncio

async def validate():
    try:
        config_manager = ConfigManager('$DB_SAFETY_CONFIG')
        await config_manager.load_config()
        print('✅ Configuration is valid')
        return True
    except Exception as e:
        print(f'❌ Configuration validation failed: {e}')
        return False

result = asyncio.run(validate())
sys.exit(0 if result else 1)
"
    
    if [ $? -eq 0 ]; then
        log "Configuration validation passed"
    else
        error "Configuration validation failed"
    fi
}

# Wait for external dependencies
wait_for_dependencies() {
    log "Checking external dependencies..."
    
    # Wait for Redis if configured
    if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
        wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis"
    fi
    
    # Wait for PostgreSQL if configured
    if [ -n "$POSTGRES_HOST" ] && [ -n "$POSTGRES_PORT" ]; then
        wait_for_service "$POSTGRES_HOST" "$POSTGRES_PORT" "PostgreSQL"
    fi
    
    # Wait for MySQL if configured
    if [ -n "$MYSQL_HOST" ] && [ -n "$MYSQL_PORT" ]; then
        wait_for_service "$MYSQL_HOST" "$MYSQL_PORT" "MySQL"
    fi
    
    # Wait for MongoDB if configured
    if [ -n "$MONGODB_HOST" ] && [ -n "$MONGODB_PORT" ]; then
        wait_for_service "$MONGODB_HOST" "$MONGODB_PORT" "MongoDB"
    fi
    
    log "Dependency check completed"
}

# Run database migrations/setup
run_setup() {
    log "Running initial setup..."
    
    # Initialize sandbox databases
    python3 -c "
import sys
sys.path.insert(0, '/app/database_safety')
import asyncio
from core.sandbox_manager import SandboxManager

async def setup():
    try:
        manager = SandboxManager()
        await manager.initialize()
        await manager.shutdown()
        print('✅ Sandbox manager initialized')
        return True
    except Exception as e:
        print(f'⚠️  Sandbox manager setup warning: {e}')
        return True  # Non-critical error

result = asyncio.run(setup())
sys.exit(0 if result else 1)
"
    
    log "Setup completed"
}

# Start the API service
start_api() {
    log "Starting Database Safety API Service..."
    log "Listening on $DB_SAFETY_HOST:$DB_SAFETY_PORT"
    log "Configuration: $DB_SAFETY_CONFIG"
    log "Log Level: $DB_SAFETY_LOG_LEVEL"
    
    cd /app/database_safety/api
    exec python3 -m uvicorn main:app \
        --host "$DB_SAFETY_HOST" \
        --port "$DB_SAFETY_PORT" \
        --log-level "${DB_SAFETY_LOG_LEVEL,,}" \
        --access-log \
        --server-header \
        --date-header
}

# Start the CLI in interactive mode
start_cli() {
    log "Starting Database Safety CLI..."
    
    if [ $# -gt 1 ]; then
        # Execute specific CLI command
        exec python3 /app/database_safety/cli/db_safety_cli.py "${@:2}"
    else
        # Interactive mode
        log "Available commands:"
        log "  db-safety --help                     # Show all available commands"
        log "  db-safety config create-default     # Create default configuration"
        log "  db-safety proxy test                # Test proxy service"
        log "  db-safety sandbox list              # List sandboxes"
        log "  db-safety system health             # System health check"
        log ""
        log "Starting interactive shell..."
        exec /bin/bash
    fi
}

# Run health check
run_health_check() {
    log "Running health check..."
    
    # Check if API service is responding
    if curl -f -s "http://localhost:$DB_SAFETY_PORT/health" > /dev/null; then
        log "✅ API service is healthy"
        return 0
    else
        error "❌ API service health check failed"
        return 1
    fi
}

# Run system tests
run_tests() {
    log "Running system tests..."
    
    python3 -c "
import sys
sys.path.insert(0, '/app/database_safety')
import asyncio
from core.query_analyzer import QuerySafetyAnalyzer
from core.data_masking import create_masking_engine

async def test_components():
    try:
        # Test query analyzer
        analyzer = QuerySafetyAnalyzer()
        analysis = await analyzer.analyze_query('SELECT 1', 'mssql')
        assert analysis.query_type.value == 'select'
        print('✅ Query analyzer test passed')
        
        # Test data masking
        engine = create_masking_engine()
        result = engine.mask_value('test@example.com', 'email', 'varchar')
        assert result.masked_value != 'test@example.com'
        print('✅ Data masking test passed')
        
        return True
    except Exception as e:
        print(f'❌ Component test failed: {e}')
        return False

result = asyncio.run(test_components())
sys.exit(0 if result else 1)
"
    
    if [ $? -eq 0 ]; then
        log "All tests passed"
    else
        error "Some tests failed"
    fi
}

# Show usage information
show_usage() {
    echo "Database Safety Layer Container"
    echo ""
    echo "Usage: docker run database-safety:latest [COMMAND] [ARGS...]"
    echo ""
    echo "Commands:"
    echo "  api                    Start HTTP API service (default)"
    echo "  cli [args]            Run CLI with optional arguments"
    echo "  health                Run health check"
    echo "  test                  Run system tests"
    echo "  shell                 Start interactive shell"
    echo "  help                  Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  DB_SAFETY_CONFIG      Configuration file path"
    echo "  DB_SAFETY_HOST        API host (default: 0.0.0.0)"
    echo "  DB_SAFETY_PORT        API port (default: 8080)"
    echo "  DB_SAFETY_LOG_LEVEL   Log level (default: INFO)"
    echo ""
    echo "Examples:"
    echo "  docker run database-safety:latest api"
    echo "  docker run database-safety:latest cli config create-default"
    echo "  docker run database-safety:latest cli sandbox list"
    echo "  docker run database-safety:latest health"
}

# Main execution logic
main() {
    log "Database Safety Layer Starting..."
    log "Version: 1.0.0"
    log "User: $(whoami)"
    log "Working Directory: $(pwd)"
    
    # Initialize
    init_directories
    validate_config
    
    # Parse command
    case "${1:-api}" in
        "api")
            wait_for_dependencies
            run_setup
            start_api
            ;;
        "cli")
            start_cli "$@"
            ;;
        "health")
            run_health_check
            ;;
        "test")
            run_tests
            ;;
        "shell")
            log "Starting interactive shell..."
            exec /bin/bash
            ;;
        "help"|"--help"|"-h")
            show_usage
            ;;
        *)
            warn "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Handle signals gracefully
trap 'log "Received shutdown signal, exiting..."; exit 0' SIGTERM SIGINT

# Execute main function
main "$@"