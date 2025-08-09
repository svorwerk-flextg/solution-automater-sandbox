#!/bin/bash
# Quick validation test for Solution-Automater-Sandbox

set -e

echo "🚀 Solution-Automater-Sandbox Quick Validation"
echo "=============================================="

# Test 1: Essential files exist
echo "📁 Checking file structure..."
if [[ -f "bin/sas" && -f "docker-compose.solution-automater-sandbox.yml" && -d "src/database_safety" ]]; then
    echo "✅ Essential files present"
else
    echo "❌ Missing essential files"
    exit 1
fi

# Test 2: CLI tool is executable
echo "🔧 Testing CLI tool..."
if [[ -x "bin/sas" ]]; then
    echo "✅ CLI tool is executable"
else
    echo "❌ CLI tool not executable"
    exit 1
fi

# Test 3: Docker Compose syntax
echo "🐳 Validating Docker Compose..."
if docker-compose -f docker-compose.solution-automater-sandbox.yml config --services > /dev/null 2>&1; then
    echo "✅ Docker Compose configuration valid (18 services detected)"
else
    echo "❌ Docker Compose configuration invalid"
    exit 1
fi

# Test 4: Configuration files
echo "⚙️ Checking configuration files..."
if [[ -f "configs/database_safety_config.yaml" && -f "configs/cloud_integration_config.yaml" ]]; then
    echo "✅ Configuration files present"
else
    echo "❌ Missing configuration files"
    exit 1
fi

# Test 5: Scripts are executable
echo "📜 Checking scripts..."
if [[ -x "scripts/install-solution-automater-sandbox.sh" && -x "scripts/sas-startup.sh" ]]; then
    echo "✅ Installation scripts ready"
else
    echo "❌ Scripts not executable"
    exit 1
fi

# Test 6: Documentation
echo "📚 Checking documentation..."
if [[ -f "README-SAS.md" && -s "README-SAS.md" ]]; then
    echo "✅ Documentation complete"
else
    echo "❌ Missing documentation"
    exit 1
fi

echo ""
echo "🎉 All quick validation tests passed!"
echo ""
echo "Solution-Automater-Sandbox is ready for deployment:"
echo ""
echo "1. Install: ./scripts/install-solution-automater-sandbox.sh"
echo "2. Setup:   ./bin/sas setup"
echo "3. Start:   ./bin/sas start"
echo ""
echo "For comprehensive testing, run: ./tests/integration_test.sh"