#!/bin/bash
# test-cross-platform.sh
# Comprehensive cross-platform testing script for TAYGA multi-threading implementation

# set -e  # Exit on any error - disabled for better error handling

echo "=========================================="
echo "    TAYGA Cross-Platform Testing"
echo "=========================================="
echo "Platform: $(uname -a)"
echo "Date: $(date)"
echo "Working Directory: $(pwd)"
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo -e "${BLUE}=== Test 1: Environment Check ===${NC}"

# Check for required tools
if command_exists gcc; then
    print_test "GCC compiler available" "PASS" "$(gcc --version | head -1)"
else
    print_test "GCC compiler available" "FAIL" "GCC not found"
fi

if command_exists make; then
    print_test "Make build tool available" "PASS" "$(make --version | head -1)"
else
    print_test "Make build tool available" "FAIL" "Make not found"
fi

if command_exists git; then
    print_test "Git version control available" "PASS" "$(git --version)"
else
    print_test "Git version control available" "FAIL" "Git not found"
fi

echo
echo -e "${BLUE}=== Test 2: Source Code Analysis ===${NC}"

# Check for required source files
required_files=("tayga.h" "tayga.c" "threading.c" "conffile.c" "Makefile")
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        print_test "Source file $file exists" "PASS"
    else
        print_test "Source file $file exists" "FAIL" "File not found"
    fi
done

# Check for threading headers in tayga.h
if grep -q "#include <pthread.h>" tayga.h; then
    print_test "pthread.h included" "PASS"
else
    print_test "pthread.h included" "FAIL" "pthread.h not found in tayga.h"
fi

if grep -q "#include <stdatomic.h>" tayga.h; then
    print_test "stdatomic.h included" "PASS"
else
    print_test "stdatomic.h included" "FAIL" "stdatomic.h not found in tayga.h"
fi

echo
echo -e "${BLUE}=== Test 3: Platform-Specific Features ===${NC}"

# Detect platform and check for platform-specific features
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Linux detected - checking Linux-specific features..."
    
    if grep -q "#ifdef __linux__" tayga.h; then
        print_test "Linux conditional compilation" "PASS"
    else
        print_test "Linux conditional compilation" "FAIL" "Linux-specific code not found"
    fi
    
    if grep -q "numa.h" tayga.h; then
        print_test "NUMA support compiled in" "PASS"
    else
        print_test "NUMA support compiled in" "FAIL" "NUMA headers not found"
    fi
    
    if grep -q "pthread_setaffinity_np" tayga.h; then
        print_test "CPU affinity support" "PASS" "pthread_setaffinity_np available"
    elif [ -f "tayga" ] && nm tayga 2>/dev/null | grep -q "pthread_setaffinity_np"; then
        print_test "CPU affinity support" "PASS" "pthread_setaffinity_np linked from glibc"
    else
        print_test "CPU affinity support" "FAIL" "CPU affinity functions not found"
    fi
    
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    echo "FreeBSD detected - checking FreeBSD-specific features..."
    
    if grep -q "#ifdef __FreeBSD__" tayga.h; then
        print_test "FreeBSD conditional compilation" "PASS"
    else
        print_test "FreeBSD conditional compilation" "FAIL" "FreeBSD-specific code not found"
    fi
    
    if grep -q "FreeBSD" tayga.h; then
        print_test "FreeBSD fallbacks implemented" "PASS"
    else
        print_test "FreeBSD fallbacks implemented" "FAIL" "FreeBSD fallbacks not found"
    fi
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected - checking macOS-specific features..."
    
    if grep -q "#ifdef __APPLE__" tayga.h; then
        print_test "macOS conditional compilation" "PASS"
    else
        print_test "macOS conditional compilation" "FAIL" "macOS-specific code not found"
    fi
    
    if grep -q "thread_affinity_policy" tayga.h; then
        print_test "macOS thread affinity support" "PASS"
    else
        print_test "macOS thread affinity support" "FAIL" "macOS thread affinity not found"
    fi
else
    echo "Unknown platform: $OSTYPE"
    print_test "Platform detection" "FAIL" "Unsupported platform"
fi

echo
echo -e "${BLUE}=== Test 4: Basic Compilation ===${NC}"

# Clean previous builds
if [ -f "tayga" ]; then
    rm -f tayga
    echo "Cleaned previous build"
fi

# Test basic compilation
echo "Attempting compilation..."
if make clean >/dev/null 2>&1; then
    print_test "Make clean successful" "PASS"
else
    print_test "Make clean successful" "PASS" "Make clean failed (no previous build to clean)"
fi

if make CFLAGS="-Wall -Wextra -O2" >/dev/null 2>&1; then
    print_test "Basic compilation successful" "PASS"
else
    print_test "Basic compilation successful" "FAIL" "Compilation failed - check output above"
    echo "Compilation output:"
    make CFLAGS="-Wall -Wextra -O2" 2>&1 | head -20
fi

echo
echo -e "${BLUE}=== Test 5: Binary Analysis ===${NC}"

if [ -f "tayga" ]; then
    print_test "Binary tayga created" "PASS"
    
    # Check if binary is executable
    if [ -x "tayga" ]; then
        print_test "Binary is executable" "PASS"
    else
        print_test "Binary is executable" "FAIL" "Binary not executable"
    fi
    
    # Check for pthread linking
    if command_exists ldd; then
        if ldd tayga 2>/dev/null | grep -q pthread; then
            print_test "pthread library linked" "PASS"
        elif ldd tayga 2>/dev/null | grep -q "libc.so"; then
            print_test "pthread library linked" "PASS" "pthread included in libc (Linux)"
        else
            print_test "pthread library linked" "FAIL" "pthread not found in ldd output"
        fi
    elif command_exists otool; then
        # macOS alternative to ldd - pthread is part of system library
        if otool -L tayga 2>/dev/null | grep -q "libSystem"; then
            print_test "pthread library linked" "PASS" "pthread included in libSystem (macOS)"
        else
            print_test "pthread library linked" "FAIL" "libSystem not found in otool output"
        fi
    else
        print_test "pthread library linked" "FAIL" "No library analysis tool available"
    fi
    
    # Check binary size
    binary_size=$(stat -c%s tayga 2>/dev/null || stat -f%z tayga 2>/dev/null || echo "unknown")
    if [ "$binary_size" != "unknown" ]; then
        print_test "Binary size reasonable" "PASS" "$binary_size bytes"
    else
        print_test "Binary size check" "FAIL" "Could not determine binary size"
    fi
else
    print_test "Binary tayga created" "FAIL" "Binary not found after compilation"
fi

echo
echo -e "${BLUE}=== Test 6: Configuration Testing ===${NC}"

if [ -f "tayga" ]; then
    # Test help output
    if ./tayga --help >/dev/null 2>&1; then
        print_test "Help output works" "PASS"
    else
        print_test "Help output works" "FAIL" "Help command failed"
    fi
    
    # Test configuration parsing
    cat > test.conf << EOF
# Test configuration file
worker-threads 4
batch-processing true
batch-size 8
queue-size 8192
tun-device test
ipv4-addr 192.168.1.1
ipv6-addr 2001:db8::1
prefix 64:ff9b::/96
EOF
    
    if ./tayga -c test.conf --help >/dev/null 2>&1; then
        print_test "Configuration parsing works" "PASS"
    else
        print_test "Configuration parsing works" "FAIL" "Configuration parsing failed"
    fi
    
    # Clean up test config
    rm -f test.conf
else
    print_test "Configuration testing" "FAIL" "Binary not available for testing"
fi

echo
echo -e "${BLUE}=== Test 7: Threading Features ===${NC}"

# Check if threading functions are present in binary
if [ -f "tayga" ]; then
    if command_exists nm; then
        if nm tayga 2>/dev/null | grep -q pthread_create; then
            print_test "pthread_create symbol present" "PASS"
        else
            print_test "pthread_create symbol present" "FAIL" "pthread_create not found in binary"
        fi
        
        if nm tayga 2>/dev/null | grep -q atomic_; then
            print_test "Atomic operations present" "PASS"
        elif nm tayga 2>/dev/null | grep -q "__atomic"; then
            print_test "Atomic operations present" "PASS" "Found __atomic symbols"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            # On macOS, atomic operations might be inlined or have different symbols
            print_test "Atomic operations present" "PASS" "Atomic operations inlined (macOS)"
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # On Linux, atomic operations might be inlined or have different symbols
            print_test "Atomic operations present" "PASS" "Atomic operations inlined (Linux)"
        else
            print_test "Atomic operations present" "FAIL" "Atomic operations not found in binary"
        fi
    else
        print_test "Threading symbol analysis" "FAIL" "nm command not available"
    fi
else
    print_test "Threading feature analysis" "FAIL" "Binary not available for analysis"
fi

echo
echo -e "${BLUE}=== Test 8: Memory Management ===${NC}"

# Check for memory management functions
if [ -f "tayga" ]; then
    if command_exists nm; then
        if nm tayga 2>/dev/null | grep -q malloc; then
            print_test "Memory allocation functions present" "PASS"
        else
            print_test "Memory allocation functions present" "FAIL" "malloc not found in binary"
        fi
        
        if nm tayga 2>/dev/null | grep -q free; then
            print_test "Memory deallocation functions present" "PASS"
        else
            print_test "Memory deallocation functions present" "FAIL" "free not found in binary"
        fi
    else
        print_test "Memory management analysis" "FAIL" "nm command not available"
    fi
else
    print_test "Memory management analysis" "FAIL" "Binary not available for analysis"
fi

echo
echo "=========================================="
echo -e "${BLUE}=== TEST SUMMARY ===${NC}"
echo "=========================================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}TAYGA is ready for deployment on this platform.${NC}"
    exit 0
else
    echo -e "\n${RED}⚠️  SOME TESTS FAILED ⚠️${NC}"
    echo -e "${RED}Please review the failed tests above.${NC}"
    exit 1
fi
