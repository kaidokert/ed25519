#!/bin/bash

# Full benchmark script for all working bigint configurations
set -e

echo "=== Ed25519 Complete Performance Benchmark ==="
echo ""

# Results storage
results_file="complete_results.md"
echo "# Ed25519 Complete Performance Results" > $results_file
echo "" >> $results_file
echo "Generated: $(date)" >> $results_file
echo "" >> $results_file
echo "| Backend | Mode | Features | Avg Time (ms) | Ops/sec | Status |" >> $results_file
echo "|---------|------|----------|---------------|---------|--------|" >> $results_file

# Function to run a single benchmark
run_benchmark() {
    local backend="$1"
    local mode="$2" 
    local features="$3"
    local description="$4"
    
    echo "Testing: $backend ($mode mode)"
    echo "Features: $features"
    echo "Description: $description"
    
    # Run the benchmark and capture output
    output=$(timeout 120s cargo run --bin generic_benchmark --features="$features" --release 2>/dev/null || echo "FAILED")
    
    if [[ "$output" == *"FAILED"* ]] || [[ "$output" == *"error"* ]] || [[ "$output" == *"❌ Benchmark failed"* ]]; then
        echo "  ❌ Failed"
        echo "| $backend | $mode | $features | FAILED | - | Error |" >> $results_file
    else
        # Extract timing results
        avg_time=$(echo "$output" | grep "Average time:" | sed 's/.*Average time: \([0-9.]*\)ms.*/\1/')
        ops_sec=$(echo "$output" | grep "Throughput:" | sed 's/.*Throughput: \([0-9.]*\) ops\/sec.*/\1/')
        
        if [[ -n "$avg_time" && "$avg_time" != "" && "$avg_time" != "0" ]]; then
            # Determine status based on performance
            if (( $(echo "$avg_time < 20" | bc -l) )); then
                status="🚀 Excellent"
            elif (( $(echo "$avg_time < 50" | bc -l) )); then
                status="✅ Good"
            elif (( $(echo "$avg_time < 100" | bc -l) )); then
                status="⚠️ Moderate"
            else
                status="🐌 Slow"
            fi
            
            echo "  ✅ ${avg_time}ms (${ops_sec} ops/sec) $status"
            echo "| $backend | $mode | $features | $avg_time | $ops_sec | $status |" >> $results_file
        else
            echo "  ❌ Parse error"
            echo "| $backend | $mode | $features | PARSE_ERROR | - | Parse Error |" >> $results_file
        fi
    fi
    
    echo ""
}

echo "Starting comprehensive benchmark..."
echo ""

# STRICT MODE configurations
echo "=== STRICT MODE BENCHMARKS ==="
run_benchmark "fixed-bigint" "strict" "fixed-bigint,fixed-bigint-u64" "u64 backend"

# Note: Other strict mode configs would need type fixes in the verify functions
# For now, focusing on working configurations

# CONSTRAINED MODE configurations  
echo "=== CONSTRAINED MODE BENCHMARKS ==="
run_benchmark "crypto-bigint-patched" "constrained" "crypto-bigint-patched" "patched version"
run_benchmark "num-bigint-patched" "constrained" "num-bigint-patched" "heap-allocated, patched"
run_benchmark "ibig-patched" "constrained" "ibig-patched" "heap-allocated, patched"

# BASIC MODE configurations
echo "=== BASIC MODE BENCHMARKS ==="
run_benchmark "bnum" "basic" "bnum" "standard version"  
run_benchmark "bnum-patched" "basic" "bnum-patched" "patched version"

echo "=== Benchmark Complete ==="
echo ""
echo "Results summary:"
cat $results_file
echo ""
echo "Full results saved to: $results_file"