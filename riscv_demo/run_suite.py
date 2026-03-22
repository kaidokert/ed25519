#!/usr/bin/env python3
"""Build and run ed25519 verification on QEMU for RISC-V sifive_e.

Generates a markdown metrics table from the results.
"""

import json
import re
import subprocess
import sys

EXAMPLES = [
    ("ed25519_u8", "u8", "baseline", ["baseline"]),
    ("ed25519_u8", "u8", "verify", []),
    ("ed25519_u32", "u32", "baseline", ["baseline"]),
    ("ed25519_u32", "u32", "verify", []),
]
TIMEOUT_RUN = 120  # seconds per QEMU run
TIMEOUT_BUILD = 600  # seconds for cargo build


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build(features):
    """Build all examples. Returns True on success."""
    args = ["cargo", "build", "--release", "--examples"]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, _out, err = run_cmd(
        args,
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print("BUILD FAILED:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(example, features):
    """Run an example via cargo run (uses .cargo/config.toml runner). Returns stdout+stderr."""
    args = ["cargo", "run", "--release", "--example", example]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, out, err = run_cmd(
        args
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"    cargo run failed (rc={rc}):", file=sys.stderr)
        print(combined, file=sys.stderr)
    return combined


def get_text_size(example, features):
    """Get .text section size via cargo-bloat JSON output."""
    try:
        args = [
            "cargo", "bloat", "--release",
            "--example", example, "--message-format=json",
        ]
        if features:
            args.extend(["--features", ",".join(features)])
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            json_line = out.strip().split('\n')[-1]
            data = json.loads(json_line)
            return data.get("text-section-size")
        else:
            print(f"    cargo-bloat failed (rc={rc}): {err.strip()}", file=sys.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    cargo-bloat not available: {e}", file=sys.stderr)
    except (json.JSONDecodeError, IndexError) as e:
        print(f"    cargo-bloat JSON parse error: {e}", file=sys.stderr)
    return None


def parse_metric(output):
    """Parse METRIC line from QEMU output. Returns dict or None."""
    m = re.search(
        r"METRIC stack:(\d+) cycles:(\d+) target:(\S+) backend:(\S+)", output
    )
    if m:
        return {
            "stack": int(m.group(1)),
            "cycles": int(m.group(2)),
            "target": m.group(3),
            "backend": m.group(4),
        }
    return None


def delta(verify_row, baseline_row, key, formatter=str):
    verify_value = verify_row.get(key)
    baseline_value = baseline_row.get(key)
    if verify_value is None or baseline_value is None:
        return "-"
    return formatter(verify_value - baseline_value)


def main():
    results = {}  # example -> {accepted, stack, cycles, text_size}
    failures = []

    print("Building for RISC-V...", file=sys.stderr)
    feature_variants = {}
    for _, _, variant, features in EXAMPLES:
        feature_key = tuple(features)
        feature_variants.setdefault(feature_key, []).append(variant)

    build_status = {}
    for feature_key, variants in feature_variants.items():
        feature_list = list(feature_key)
        build_ok = build(feature_list)
        build_status[feature_key] = build_ok
        if not build_ok:
            joined_variants = ", ".join(sorted(set(variants)))
            failures = [f"Build failed: {joined_variants}"]
            print(f"\nFailures: {len(failures)}", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            return 1

    for example, backend, variant, features in EXAMPLES:
        feature_key = tuple(features)
        if not build_status.get(feature_key, False):
            continue
        print(f"  Running {example} on QEMU sifive_e...", file=sys.stderr)
        try:
            output = run_qemu(example, features)
        except subprocess.TimeoutExpired:
            print("    TIMEOUT", file=sys.stderr)
            failures.append(f"Timeout: {example}")
            continue

        accepted = "ed25519 ACCEPT" in output
        metric = parse_metric(output)
        text_size = get_text_size(example, features)

        status = "ACCEPT" if accepted else "REJECT"
        print(f"    {status}", file=sys.stderr)

        if not metric:
            print("    METRIC line missing", file=sys.stderr)
            failures.append(f"Missing METRIC: {example}")
        if text_size is None:
            print("    .text size unavailable", file=sys.stderr)
            failures.append(f"Missing .text size: {example}")
        if not accepted:
            failures.append(f"REJECT: {example}")

        results[(backend, variant)] = {
            "accepted": accepted,
            "stack": metric["stack"] if metric else None,
            "cycles": metric["cycles"] if metric else None,
            "text_size": text_size,
        }

    # Generate markdown table
    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate cycle cost of signature verification.")
    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|---------|-------------|---------------|-------------------|")

    for backend in ("u8", "u32"):
        verify = results.get((backend, "verify"))
        baseline = results.get((backend, "baseline"))
        if verify is None or baseline is None:
            print(f"| sifive_e (RV32) | {backend} | - | - | - |")
            continue
        delta_text = delta(
            verify,
            baseline,
            "text_size",
            formatter=lambda value: f"{value / 1024:.1f}",
        )
        delta_stack = delta(verify, baseline, "stack")
        delta_cycles = delta(verify, baseline, "cycles")
        print(f"| sifive_e (RV32) | {backend} | {delta_text} | {delta_stack} | {delta_cycles} |")

    print()
    print("Approx cycles are derived from the demo harness counters and should be treated as a rough instruction-cost proxy, not a precise benchmark.")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
