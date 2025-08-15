#!/bin/bash

# Comprehensive benchmark script for all bignum backends and arithmetic modes
set -e

echo "=== Ed25519 Comprehensive Performance Benchmark ==="
echo "Testing all bignum backends with different arithmetic modes"
echo ""

# Results storage
results_file="benchmark_results.md"
echo "# Ed25519 Performance Benchmark Results" > $results_file
echo "" >> $results_file
echo "| Backend | Mode | Features | Avg Time (ms) | Ops/sec | Notes |" >> $results_file
echo "|---------|------|----------|---------------|---------|-------|" >> $results_file

# Function to run a single benchmark
run_benchmark() {
    local backend="$1"
    local mode="$2"
    local features="$3"
    local notes="$4"
    
    echo "Testing: $backend ($mode mode) with features: $features"
    
    # Run the benchmark and capture output
    output=$(timeout 60s cargo run --bin benchmark_comprehensive --features="$features" --release 2>/dev/null || echo "TIMEOUT/ERROR")
    
    if [[ "$output" == *"TIMEOUT/ERROR"* ]]; then
        echo "  ❌ Failed or timed out"
        echo "| $backend | $mode | $features | TIMEOUT | - | $notes |" >> $results_file
    else
        # Extract average time and ops/sec
        avg_time=$(echo "$output" | grep "Average time:" | sed 's/.*Average time: \([0-9.]*\)ms.*/\1/')
        ops_sec=$(echo "$output" | grep "Throughput:" | sed 's/.*Throughput: \([0-9.]*\) ops\/sec.*/\1/')
        
        if [[ -n "$avg_time" && -n "$ops_sec" ]]; then
            echo "  ✅ $avg_time ms ($ops_sec ops/sec)"
            echo "| $backend | $mode | $features | $avg_time | $ops_sec | $notes |" >> $results_file
        else
            echo "  ❌ Could not parse results"
            echo "| $backend | $mode | $features | ERROR | - | Parse error - $notes |" >> $results_file
        fi
    fi
    
    echo ""
}

# Test configurations
echo "Starting benchmark runs..."
echo ""

# Fixed-bigint configurations (strict mode)
run_benchmark "fixed-bigint" "strict" "fixed-bigint" "u32 backend"
run_benchmark "fixed-bigint" "strict" "fixed-bigint,fixed-bigint-u64" "u64 backend"  
run_benchmark "fixed-bigint" "strict" "fixed-bigint,fixed-bigint-u64,montgomery" "u64 + Montgomery"

# Num-bigint configurations (basic mode)
run_benchmark "num-bigint" "basic" "num-bigint" "standard"
run_benchmark "num-bigint-patched" "basic" "num-bigint-patched" "patched version"

# Bnum configurations (basic mode)  
run_benchmark "bnum" "basic" "bnum" "standard"
run_benchmark "bnum-patched" "basic" "bnum-patched" "patched version"

# Crypto-bigint configurations (constrained mode)
run_benchmark "crypto-bigint" "constrained" "crypto-bigint" "standard"
run_benchmark "crypto-bigint-patched" "constrained" "crypto-bigint-patched" "patched version"

# IBig configurations (basic mode)
run_benchmark "ibig" "basic" "ibig" "standard"
run_benchmark "ibig-patched" "basic" "ibig-patched" "patched version"

echo "=== Benchmark Complete ==="
echo "Results saved to: $results_file"
echo ""
echo "Summary:"
cat $results_file