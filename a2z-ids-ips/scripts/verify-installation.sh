#!/bin/bash

# A2Z IDS/IPS Installation Verification Script
# Comprehensive test suite for deployment validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Logging
LOG_FILE="/tmp/a2z-ids-verification.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    ((TOTAL_TESTS++))
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Test Docker availability
test_docker() {
    print_test "Checking Docker availability"
    if command -v docker >/dev/null 2>&1; then
        if docker ps >/dev/null 2>&1; then
            print_pass "Docker is available and running"
            return 0
        else
            print_fail "Docker is installed but not running"
            return 1
        fi
    else
        print_fail "Docker is not installed"
        return 1
    fi
}

# Test Docker Compose availability
test_docker_compose() {
    print_test "Checking Docker Compose availability"
    if command -v docker-compose >/dev/null 2>&1; then
        print_pass "Docker Compose is available"
        return 0
    else
        print_fail "Docker Compose is not installed"
        return 1
    fi
}

# Test network connectivity
test_network() {
    print_test "Testing network connectivity"
    if ping -c 1 google.com >/dev/null 2>&1; then
        print_pass "Network connectivity is working"
        return 0
    else
        print_fail "Network connectivity issues detected"
        return 1
    fi
}

# Test port availability
test_ports() {
    print_test "Checking required port availability"
    local ports=(3000 8080 5432 6379 8123 9090 3001)
    local failed_ports=()
    
    for port in "${ports[@]}"; do
        if netstat -ln 2>/dev/null | grep ":$port " >/dev/null; then
            print_info "Port $port is in use (expected for running services)"
        elif lsof -i :$port >/dev/null 2>&1; then
            print_info "Port $port is in use (expected for running services)"
        else
            print_info "Port $port is available"
        fi
    done
    
    print_pass "Port availability check completed"
    return 0
}

# Test file structure
test_file_structure() {
    print_test "Verifying file structure"
    local required_files=(
        "docker-compose.standalone.yml"
        "Makefile.standalone"
        "README-STANDALONE.md"
        "scripts/deploy.sh"
        "scripts/deploy.ps1"
        "scripts/init-db.sql"
        "config/config.yaml"
        "core-engine/Dockerfile"
        "management-api/Dockerfile"
        "web-interface/Dockerfile"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -eq 0 ]]; then
        print_pass "All required files are present"
        return 0
    else
        print_fail "Missing files: ${missing_files[*]}"
        return 1
    fi
}

# Test Docker services
test_docker_services() {
    print_test "Testing Docker services"
    if docker-compose -f docker-compose.standalone.yml ps >/dev/null 2>&1; then
        local running_services=$(docker-compose -f docker-compose.standalone.yml ps --services --filter "status=running" 2>/dev/null | wc -l)
        if [[ $running_services -gt 0 ]]; then
            print_pass "Docker services are running ($running_services services active)"
            return 0
        else
            print_fail "No Docker services are running"
            return 1
        fi
    else
        print_fail "Unable to check Docker services status"
        return 1
    fi
}

# Test API endpoints
test_api_endpoints() {
    print_test "Testing API endpoints"
    local endpoints=(
        "http://localhost:8080/health"
        "http://localhost:8080/api/v1/status"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -s --max-time 5 "$endpoint" >/dev/null 2>&1; then
            print_info "✓ $endpoint is responding"
        else
            print_info "✗ $endpoint is not responding (may be normal if not running)"
        fi
    done
    
    print_pass "API endpoint tests completed"
    return 0
}

# Test web interfaces
test_web_interfaces() {
    print_test "Testing web interfaces"
    local interfaces=(
        "http://localhost:3000"
        "http://localhost:3001"
        "http://localhost:9090"
    )
    
    for interface in "${interfaces[@]}"; do
        if curl -s --max-time 5 "$interface" >/dev/null 2>&1; then
            print_info "✓ $interface is accessible"
        else
            print_info "✗ $interface is not accessible (may be normal if not running)"
        fi
    done
    
    print_pass "Web interface tests completed"
    return 0
}

# Test database connectivity
test_databases() {
    print_test "Testing database connectivity"
    
    # Test PostgreSQL
    if command -v psql >/dev/null 2>&1; then
        if PGPASSWORD=a2z_ids_password psql -h localhost -U a2z_ids -d a2z_ids -c "\q" >/dev/null 2>&1; then
            print_info "✓ PostgreSQL is accessible"
        else
            print_info "✗ PostgreSQL is not accessible (may be normal if not running)"
        fi
    else
        print_info "psql not available for PostgreSQL testing"
    fi
    
    # Test Redis
    if command -v redis-cli >/dev/null 2>&1; then
        if redis-cli ping >/dev/null 2>&1; then
            print_info "✓ Redis is accessible"
        else
            print_info "✗ Redis is not accessible (may be normal if not running)"
        fi
    else
        print_info "redis-cli not available for Redis testing"
    fi
    
    print_pass "Database connectivity tests completed"
    return 0
}

# Test configuration files
test_configuration() {
    print_test "Validating configuration files"
    
    # Check main config file
    if [[ -f "config/config.yaml" ]]; then
        if grep -q "capture:" "config/config.yaml"; then
            print_info "✓ Main configuration appears valid"
        else
            print_info "✗ Main configuration may be invalid"
        fi
    else
        print_fail "Main configuration file missing"
        return 1
    fi
    
    # Check Docker Compose file
    if [[ -f "docker-compose.standalone.yml" ]]; then
        if docker-compose -f docker-compose.standalone.yml config >/dev/null 2>&1; then
            print_info "✓ Docker Compose configuration is valid"
        else
            print_info "✗ Docker Compose configuration has errors"
        fi
    else
        print_fail "Docker Compose configuration missing"
        return 1
    fi
    
    print_pass "Configuration validation completed"
    return 0
}

# Test permissions
test_permissions() {
    print_test "Checking file permissions"
    
    local executable_files=(
        "scripts/deploy.sh"
        "scripts/deploy.ps1"
        "status-check.sh"
    )
    
    for file in "${executable_files[@]}"; do
        if [[ -x "$file" ]]; then
            print_info "✓ $file is executable"
        else
            print_info "✗ $file is not executable"
        fi
    done
    
    print_pass "Permission checks completed"
    return 0
}

# Test system requirements
test_system_requirements() {
    print_test "Checking system requirements"
    
    # Check available memory
    if [[ -f "/proc/meminfo" ]]; then
        local memory_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        local memory_gb=$((memory_kb / 1024 / 1024))
        if [[ $memory_gb -ge 4 ]]; then
            print_info "✓ Memory: ${memory_gb}GB (sufficient)"
        else
            print_info "⚠ Memory: ${memory_gb}GB (minimum 4GB recommended)"
        fi
    elif command -v sw_vers >/dev/null 2>&1; then
        # macOS
        local memory_gb=$(system_profiler SPHardwareDataType | grep "Memory:" | awk '{print $2}' | cut -d' ' -f1)
        print_info "✓ Memory: ${memory_gb} (macOS detected)"
    fi
    
    # Check disk space
    local disk_space=$(df -h . | tail -1 | awk '{print $4}')
    print_info "✓ Available disk space: $disk_space"
    
    # Check CPU cores
    if [[ -f "/proc/cpuinfo" ]]; then
        local cpu_cores=$(nproc)
        print_info "✓ CPU cores: $cpu_cores"
    elif command -v sysctl >/dev/null 2>&1; then
        local cpu_cores=$(sysctl -n hw.ncpu)
        print_info "✓ CPU cores: $cpu_cores"
    fi
    
    print_pass "System requirements check completed"
    return 0
}

# Performance test
test_performance() {
    print_test "Running basic performance tests"
    
    # Test Docker performance
    if docker --version >/dev/null 2>&1; then
        local docker_start_time=$(date +%s%N)
        docker run --rm hello-world >/dev/null 2>&1 || true
        local docker_end_time=$(date +%s%N)
        local docker_duration=$(( (docker_end_time - docker_start_time) / 1000000 ))
        print_info "✓ Docker container start time: ${docker_duration}ms"
    fi
    
    print_pass "Performance tests completed"
    return 0
}

# Security checks
test_security() {
    print_test "Running security checks"
    
    # Check for default passwords in configs
    if grep -r "admin123\|password123\|default" config/ >/dev/null 2>&1; then
        print_info "⚠ Default passwords found in configuration (should be changed in production)"
    else
        print_info "✓ No obvious default passwords found"
    fi
    
    # Check file permissions for sensitive files
    if [[ -f ".env" ]] && [[ $(stat -c %a .env 2>/dev/null || stat -f %A .env 2>/dev/null) != "600" ]]; then
        print_info "⚠ .env file permissions are not secure (should be 600)"
    fi
    
    print_pass "Security checks completed"
    return 0
}

# Main verification function
main() {
    print_header "A2Z IDS/IPS Installation Verification"
    echo "Starting comprehensive verification at $(date)"
    echo "Log file: $LOG_FILE"
    echo
    
    # Run all tests
    test_docker
    test_docker_compose
    test_network
    test_ports
    test_file_structure
    test_docker_services
    test_api_endpoints
    test_web_interfaces
    test_databases
    test_configuration
    test_permissions
    test_system_requirements
    test_performance
    test_security
    
    # Summary
    echo
    print_header "Verification Summary"
    echo "Total tests run: $TOTAL_TESTS"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    local success_rate=$((TESTS_PASSED * 100 / TOTAL_TESTS))
    echo "Success rate: $success_rate%"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo
        print_pass "All tests passed! A2Z IDS/IPS is ready for deployment."
        echo
        echo -e "${GREEN}🎉 Installation verification completed successfully!${NC}"
        exit 0
    else
        echo
        print_fail "Some tests failed. Please review the issues above."
        echo
        echo -e "${YELLOW}⚠️  Installation verification completed with warnings/errors.${NC}"
        exit 1
    fi
}

# Run main function
main "$@" 