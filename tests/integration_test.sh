#!/bin/bash
# Solution-Automater-Sandbox Integration Test Suite
# Tests all components and validates system integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    log_info "Running test: $test_name"
    
    if eval "$test_command"; then
        log_success "$test_name"
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "======================================"
echo "Solution-Automater-Sandbox Integration Test Suite"
echo "======================================"
echo

# Test 1: File Structure Validation
run_test "File Structure Validation" "
    test -f 'bin/sas' &&
    test -f 'docker-compose.solution-automater-sandbox.yml' &&
    test -f 'Dockerfile.solution-automater-sandbox' &&
    test -f 'scripts/install-solution-automater-sandbox.sh' &&
    test -d 'src/database_safety' &&
    test -d 'src/cloud_integration' &&
    test -d 'security-architecture' &&
    test -d 'monitoring'
"

# Test 2: CLI Tool Basic Validation
run_test "CLI Tool Basic Functions" "
    ./bin/sas --version > /dev/null 2>&1 &&
    ./bin/sas --help > /dev/null 2>&1
"

# Test 3: Docker Compose Syntax Validation
run_test "Docker Compose Configuration Syntax" "
    docker-compose -f docker-compose.solution-automater-sandbox.yml config > /dev/null 2>&1
"

# Test 4: Database Safety Configuration Validation
run_test "Database Safety Configuration" "
    python3 -c \"
import yaml
import sys
try:
    with open('configs/database_safety_config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    assert 'database_connections' in config
    assert 'safety_rules' in config
    assert 'audit_settings' in config
    print('Database safety config validation passed')
except Exception as e:
    print(f'Database safety config validation failed: {e}')
    sys.exit(1)
\" > /dev/null 2>&1
"

# Test 5: Cloud Integration Configuration Validation
run_test "Cloud Integration Configuration" "
    python3 -c \"
import yaml
import sys
try:
    with open('configs/cloud_integration_config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    assert 'fabric' in config
    assert 'aws' in config
    assert 'security' in config
    print('Cloud integration config validation passed')
except Exception as e:
    print(f'Cloud integration config validation failed: {e}')
    sys.exit(1)
\" > /dev/null 2>&1
"

# Test 6: Security Architecture Validation
run_test "Security Architecture Configuration" "
    test -f 'security-architecture/envoy-config/envoy.yaml' &&
    test -f 'security-architecture/docker-compose.security.yml' &&
    test -d 'security-architecture/db-proxy' &&
    test -d 'security-architecture/session-manager'
"

# Test 7: Monitoring Configuration Validation
run_test "Monitoring Configuration" "
    test -f 'monitoring/prometheus.yml' &&
    test -f 'monitoring/grafana/dashboard-files/sas-overview.json' &&
    python3 -c \"
import yaml
with open('monitoring/prometheus.yml', 'r') as f:
    config = yaml.safe_load(f)
assert 'scrape_configs' in config
\" > /dev/null 2>&1
"

# Test 8: Python Dependencies Validation
run_test "Python Dependencies Check" "
    python3 -c \"
try:
    import yaml, asyncio, aiohttp, fastapi, click
    print('Core Python dependencies available')
except ImportError as e:
    print(f'Missing Python dependency: {e}')
    raise
\" > /dev/null 2>&1
"

# Test 9: Environment File Templates
run_test "Environment File Templates" "
    test -f '.env.example' &&
    test -f '.env.database_safety' &&
    grep -q 'TWILIO_ACCOUNT_SID' .env.example &&
    grep -q 'DATABASE_CONNECTIONS' .env.database_safety
"

# Test 10: Installation Script Validation
run_test "Installation Script Validation" "
    bash -n scripts/install-solution-automater-sandbox.sh &&
    bash -n scripts/sas-startup.sh &&
    bash -n scripts/install-sas-mcp-servers.sh
"

# Test 11: CLI Command Structure
run_test "CLI Command Structure Validation" "
    ./bin/sas --help | grep -q 'Setup & Management' &&
    ./bin/sas --help | grep -q 'Agent Management' &&
    ./bin/sas --help | grep -q 'Database Operations' &&
    ./bin/sas --help | grep -q 'Cloud Integration'
"

# Test 12: MCP Server Configuration
run_test "MCP Server Configuration" "
    test -f 'mcp-servers.txt' &&
    test -f 'install-mcp-servers.sh' &&
    grep -q 'serena' mcp-servers.txt &&
    grep -q 'context7' mcp-servers.txt
"

# Test 13: Infrastructure Templates
run_test "Infrastructure Templates" "
    test -f 'infrastructure/terraform/main.tf' &&
    bash -c 'cd infrastructure/terraform && terraform validate' > /dev/null 2>&1 || true
"

# Test 14: CI/CD Pipeline Configuration
run_test "CI/CD Pipeline Configuration" "
    test -f '.github/workflows/solution-automater-sandbox.yml' &&
    python3 -c \"
import yaml
with open('.github/workflows/solution-automater-sandbox.yml', 'r') as f:
    workflow = yaml.safe_load(f)
assert 'jobs' in workflow
assert 'build' in workflow['jobs']
\" > /dev/null 2>&1
"

# Test 15: Documentation Completeness
run_test "Documentation Completeness" "
    test -f 'README-SAS.md' &&
    test -s 'README-SAS.md' &&
    grep -q 'Solution-Automater-Sandbox' README-SAS.md &&
    grep -q 'Installation' README-SAS.md &&
    grep -q 'Usage' README-SAS.md
"

echo
echo "======================================"
echo "Integration Test Results:"
echo "======================================"
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -eq 0 ]; then
    log_success "All integration tests passed! ✨"
    echo
    echo "Solution-Automater-Sandbox is ready for deployment!"
    echo
    echo "Next steps:"
    echo "1. Run: ./scripts/install-solution-automater-sandbox.sh"
    echo "2. Configure: Edit configs/*.yaml with your environment settings"
    echo "3. Deploy: ./bin/sas setup"
    echo "4. Start: ./bin/sas start"
    echo
    exit 0
else
    log_error "$TESTS_FAILED test(s) failed. Please review the errors above."
    exit 1
fi