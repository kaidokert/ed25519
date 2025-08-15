#!/bin/bash

# Targeted benchmark script for correct bignum/mode combinations
set -e

echo "=== Ed25519 Performance Benchmark (Correct Configurations) ==="
echo ""

# Results storage
results_file="performance_results.md"
echo "# Ed25519 Performance Benchmark Results" > $results_file
echo "" >> $results_file
echo "Generated: $(date)" >> $results_file
echo "" >> $results_file
echo "| Backend | Mode | Features | Total Time (ms) | Point Mul Time (ms) | Ops/sec | Notes |" >> $results_file
echo "|---------|------|----------|------------------|---------------------|---------|-------|" >> $results_file

# Function to run a single benchmark and extract timing
run_benchmark() {
    local backend="$1"
    local mode="$2"
    local features="$3"
    local notes="$4"
    
    echo "Testing: $backend ($mode mode) with features: $features"
    
    # Determine which binary to use based on features
    if [[ "$features" == *"fixed-bigint"* ]]; then
        binary="verify_baked"
    else
        echo "  ❌ Skipped - no suitable binary for non-fixed-bigint backends"
        echo "| $backend | $mode | $features | N/A | N/A | N/A | No binary available |" >> $results_file
        echo ""
        return
    fi
    
    # Run the benchmark and capture output
    output=$(timeout 60s cargo run --bin $binary --features="$features" --release 2>/dev/null || echo "TIMEOUT/ERROR")
    
    if [[ "$output" == *"TIMEOUT/ERROR"* ]] || [[ "$output" == *"error"* ]]; then
        echo "  ❌ Failed or timed out"
        echo "| $backend | $mode | $features | TIMEOUT | - | - | Failed/timeout |" >> $results_file
    else
        # Extract total time and point multiplication times
        total_time=$(echo "$output" | grep "TOTAL verify()" | sed 's/.*TOTAL verify() took \([0-9.]*\)ms.*/\1/')
        point_mul_s=$(echo "$output" | grep "point_mul(s, g)" | sed 's/.*point_mul(s, g) took \([0-9.]*\)ms.*/\1/')
        point_mul_h=$(echo "$output" | grep "point_mul(h, aa)" | sed 's/.*point_mul(h, aa) took \([0-9.]*\)ms.*/\1/')
        
        if [[ -n "$total_time" && "$total_time" != "0" ]]; then
            # Calculate point mul total and ops/sec
            if [[ -n "$point_mul_s" && -n "$point_mul_h" ]]; then
                point_mul_total=$(echo "$point_mul_s + $point_mul_h" | bc -l)
            else
                point_mul_total="N/A"
            fi
            
            ops_sec=$(echo "scale=1; 1000 / $total_time" | bc -l)
            echo "  ✅ ${total_time}ms total, point_mul: ${point_mul_total}ms, ${ops_sec} ops/sec"
            echo "| $backend | $mode | $features | $total_time | $point_mul_total | $ops_sec | $notes |" >> $results_file
        else
            echo "  ❌ Could not parse results"
            echo "| $backend | $mode | $features | ERROR | - | - | Parse error |" >> $results_file
        fi
    fi
    
    echo ""
}

echo "Starting benchmark runs..."
echo ""

# STRICT MODE (fixed-bigint only)
echo "=== STRICT MODE ==="
run_benchmark "fixed-bigint" "strict" "fixed-bigint,fixed-bigint-u64" "u64 backend, best performance"

# CONSTRAINED MODE (all crates work)  
echo "=== CONSTRAINED MODE ==="
run_benchmark "crypto-bigint" "constrained" "crypto-bigint" "standard version"
run_benchmark "crypto-bigint-patched" "constrained" "crypto-bigint-patched" "patched version"
# Note: num-bigint and ibig constrained would need different binaries - skip for now

# BASIC MODE (Copy crates only - no num-bigint/ibig)
echo "=== BASIC MODE ==="  
run_benchmark "bnum" "basic" "bnum" "standard version"
run_benchmark "bnum-patched" "basic" "bnum-patched" "patched version"

echo "=== Benchmark Complete ==="
echo "Results saved to: $results_file"
echo ""
echo "Summary:"
cat $results_file