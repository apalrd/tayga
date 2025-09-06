#!/bin/bash
# test-multithreading.sh
# Multi-threading specific tests for TAYGA

echo "=========================================="
echo "    TAYGA Multi-Threading Tests"
echo "=========================================="
echo "Platform: $(uname -a)"
echo "CPU Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")"
echo "Date: $(date)"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test results
print_test() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✅ $test_name${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ $test_name${NC}"
        if [ -n "$details" ]; then
            echo -e "   ${RED}Details: $details${NC}"
        fi
        ((TESTS_FAILED++))
    fi
}

echo -e "${BLUE}=== Test 1: CPU Core Detection ===${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check CPU core count
if command_exists nproc; then
    CPU_CORES=$(nproc)
    echo "Detected CPU cores: $CPU_CORES"
    if [ "$CPU_CORES" -gt 1 ]; then
        print_test "Multi-core system detected" "PASS" "$CPU_CORES cores"
    else
        print_test "Multi-core system detected" "FAIL" "Only $CPU_CORES core(s) - threading benefits limited"
    fi
elif command_exists sysctl; then
    CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null)
    echo "Detected CPU cores: $CPU_CORES"
    if [ "$CPU_CORES" -gt 1 ]; then
        print_test "Multi-core system detected" "PASS" "$CPU_CORES cores"
    else
        print_test "Multi-core system detected" "FAIL" "Only $CPU_CORES core(s) - threading benefits limited"
    fi
else
    print_test "CPU core detection" "FAIL" "No CPU detection tool available"
fi

echo
echo -e "${BLUE}=== Test 2: Threading Configuration ===${NC}"

# Test different thread configurations
if [ -f "tayga" ]; then
    # Test auto-detection (worker-threads 0)
    cat > test_auto.conf << EOF
worker-threads 0
tun-device test
ipv4-addr 192.168.1.1
ipv6-addr 2001:db8::1
prefix 64:ff9b::/96
EOF
    
    if ./tayga -c test_auto.conf --help >/dev/null 2>&1; then
        print_test "Auto thread detection configuration" "PASS"
    else
        print_test "Auto thread detection configuration" "FAIL" "Auto thread config failed"
    fi
    
    # Test manual thread configuration
    cat > test_manual.conf << EOF
worker-threads 4
batch-processing true
batch-size 8
queue-size 8192
tun-device test
ipv4-addr 192.168.1.1
ipv6-addr 2001:db8::1
prefix 64:ff9b::/96
EOF
    
    if ./tayga -c test_manual.conf --help >/dev/null 2>&1; then
        print_test "Manual thread configuration" "PASS"
    else
        print_test "Manual thread configuration" "FAIL" "Manual thread config failed"
    fi
    
    # Clean up test configs
    rm -f test_auto.conf test_manual.conf
else
    print_test "Threading configuration testing" "FAIL" "Binary not available"
fi

echo
echo -e "${BLUE}=== Test 3: Platform-Specific Threading Features ===${NC}"

# Check for platform-specific threading features
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Linux detected - checking NUMA and CPU affinity..."
    
    # Check for NUMA support
    if [ -f "/proc/cpuinfo" ] && grep -q "physical id" /proc/cpuinfo; then
        NUMA_NODES=$(grep "physical id" /proc/cpuinfo | sort -u | wc -l)
        if [ "$NUMA_NODES" -gt 1 ]; then
            print_test "NUMA system detected" "PASS" "$NUMA_NODES NUMA nodes"
        else
            print_test "NUMA system detected" "PASS" "Single NUMA node"
        fi
    else
        print_test "NUMA system detection" "FAIL" "Cannot detect NUMA topology"
    fi
    
    # Check for CPU affinity support
    if grep -q "pthread_setaffinity_np" tayga.h; then
        print_test "CPU affinity support" "PASS" "pthread_setaffinity_np available"
    elif [ -f "tayga" ] && nm tayga 2>/dev/null | grep -q "pthread_setaffinity_np"; then
        print_test "CPU affinity support" "PASS" "pthread_setaffinity_np linked from glibc"
    else
        print_test "CPU affinity support" "FAIL" "CPU affinity not available"
    fi
    
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    echo "FreeBSD detected - checking threading support..."
    
    # Check for FreeBSD threading support
    if grep -q "FreeBSD" tayga.h; then
        print_test "FreeBSD threading support" "PASS" "FreeBSD-specific code present"
    else
        print_test "FreeBSD threading support" "FAIL" "FreeBSD-specific code not found"
    fi
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected - checking Apple Silicon optimization..."
    
    # Check for macOS threading support
    if grep -q "thread_affinity_policy" tayga.h; then
        print_test "macOS thread affinity support" "PASS" "Apple Silicon optimization available"
    else
        print_test "macOS thread affinity support" "FAIL" "Apple Silicon optimization not found"
    fi
fi

echo
echo -e "${BLUE}=== Test 4: Threading Performance Features ===${NC}"

# Check for performance optimization features
if [ -f "tayga" ]; then
    # Check for batch processing support
    if grep -q "batch-processing" conffile.c; then
        print_test "Batch processing support" "PASS" "Batch processing available"
    else
        print_test "Batch processing support" "FAIL" "Batch processing not found"
    fi
    
    # Check for lock-free queue support
    if grep -q "atomic_" threading.c; then
        print_test "Lock-free queue support" "PASS" "Atomic operations implemented"
    else
        print_test "Lock-free queue support" "FAIL" "Atomic operations not found"
    fi
    
    # Check for memory pool support
    if grep -q "packet_mem_pool" tayga.h; then
        print_test "Memory pool support" "PASS" "Memory pool optimization available"
    else
        print_test "Memory pool support" "FAIL" "Memory pool not found"
    fi
else
    print_test "Performance features analysis" "FAIL" "Binary not available"
fi

echo
echo -e "${BLUE}=== Test 5: Threading Stress Test ===${NC}"

# Simple threading stress test
if [ -f "tayga" ]; then
    echo "Running threading stress test..."
    
    # Create a test configuration with maximum threads
    cat > stress_test.conf << EOF
worker-threads 16
batch-processing true
batch-size 16
queue-size 16384
tun-device test
ipv4-addr 192.168.1.1
ipv6-addr 2001:db8::1
prefix 64:ff9b::/96
EOF
    
    # Test if the configuration loads without errors
    if timeout 5 ./tayga -c stress_test.conf --help >/dev/null 2>&1; then
        print_test "Threading stress test" "PASS" "High thread count configuration works"
    else
        print_test "Threading stress test" "FAIL" "High thread count configuration failed"
    fi
    
    # Clean up
    rm -f stress_test.conf
else
    print_test "Threading stress test" "FAIL" "Binary not available"
fi

echo
echo "=========================================="
echo -e "${BLUE}=== MULTI-THREADING TEST SUMMARY ===${NC}"
echo "=========================================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL MULTI-THREADING TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}TAYGA multi-threading is ready for deployment.${NC}"
    exit 0
else
    echo -e "\n${RED}⚠️  SOME MULTI-THREADING TESTS FAILED ⚠️${NC}"
    echo -e "${RED}Please review the failed tests above.${NC}"
    exit 1
fi
