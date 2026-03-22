#!/usr/bin/env python3
"""Build and run ed25519 examples on QEMU for all Cortex-M targets.

Generates a markdown metrics table from the results.
"""

import json
import re
import subprocess
import sys

EXAMPLES = [
    ("ed25519_u8", "u8", "placebo", ["baseline"]),
    ("ed25519_u8", "u8", "verify", []),
    ("ed25519_u32", "u32", "placebo", ["baseline"]),
    ("ed25519_u32", "u32", "verify", []),
]
TARGETS = [
    ("thumbv6m-none-eabi", "M0"),
    ("thumbv7m-none-eabi", "M3"),
    ("thumbv7em-none-eabi", "M4"),
]
TIMEOUT_RUN = 120  # seconds per QEMU run
TIMEOUT_BUILD = 600  # seconds for cargo build


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build_examples(target, features):
    """Build all examples for a target. Returns True on success."""
    args = ["cargo", "build", "--target", target, "--release", "--examples"]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, _out, err = run_cmd(
        args,
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print(f"BUILD FAILED for {target}:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example, features):
    """Run an example on QEMU via cargo run. Returns stdout+stderr."""
    args = ["cargo", "run", "--target", target, "--release", "--example", example]
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


def get_text_size(target, example, features):
    """Get .text section size via cargo-bloat JSON output."""
    try:
        args = [
            "cargo", "bloat", "--release", "--target", target,
            "--example", example, "--message-format=json",
        ]
        if features:
            args.extend(["--features", ",".join(features)])
        rc, out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
        if rc == 0:
            # JSON is on the last line of output
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


def main():
    results = {}  # (example, target) -> {stack, cycles, text_size, accepted}
    failures = []

    for target, label in TARGETS:
        print(f"Building for {target}...", file=sys.stderr)
        for _, _, variant, features in EXAMPLES:
            if not build_examples(target, features):
                failures.append(f"Build failed: {target} ({variant})")
                continue
        for example, backend, variant, features in EXAMPLES:
            key = (backend, variant, target)
            print(f"  Running {example} on {label}...", file=sys.stderr)
            try:
                output = run_qemu(target, example, features)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} on {label}")
                continue

            accepted = "ed25519 ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example, features)

            if not metric:
                print(f"    METRIC line missing", file=sys.stderr)
                failures.append(f"Missing METRIC: {example} on {label}")
            if text_size is None:
                print(f"    .text size unavailable", file=sys.stderr)
                failures.append(f"Missing .text size: {example} on {label}")

            results[key] = {
                "accepted": accepted,
                "backend": backend,
                "variant": variant,
                "stack": metric["stack"] if metric else None,
                "cycles": metric["cycles"] if metric else None,
                "text_size": text_size,
            }

            status = "ACCEPT" if accepted else "REJECT"
            print(f"    {status}", file=sys.stderr)
            if not accepted:
                failures.append(f"REJECT: {example} on {label}")

    print()
    print("Metrics below are verify-minus-baseline deltas: the incremental flash, stack, and approximate cycle cost of signature verification.")
    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|---------|-------------|---------------|-------------------|")
    for target, label in TARGETS:
        for backend in ("u8", "u32"):
            verify_row = results.get((backend, "verify", target))
            placebo_row = results.get((backend, "placebo", target))
            if verify_row is None or placebo_row is None:
                print(f"| {label} | {backend} | - | - | - |")
                continue
            delta_text = (
                f"{(verify_row['text_size'] - placebo_row['text_size']) / 1024:.1f}"
                if verify_row["text_size"] is not None and placebo_row["text_size"] is not None else "-"
            )
            delta_stack = (
                str(verify_row["stack"] - placebo_row["stack"])
                if verify_row["stack"] is not None and placebo_row["stack"] is not None else "-"
            )
            delta_cycles = (
                str(verify_row["cycles"] - placebo_row["cycles"])
                if verify_row["cycles"] is not None and placebo_row["cycles"] is not None else "-"
            )
            print(f"| {label} | {backend} | {delta_text} | {delta_stack} | {delta_cycles} |")

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
