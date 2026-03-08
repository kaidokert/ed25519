#!/usr/bin/env python3
"""Build and run ed25519 examples on QEMU for all Cortex-M targets.

Generates a markdown metrics table from the results.
"""

import re
import subprocess
import sys

EXAMPLES = ["ed25519_u8", "ed25519_u32"]
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


def build_examples(target):
    """Build all examples for a target. Returns True on success."""
    rc, _out, err = run_cmd(
        ["cargo", "build", "--target", target, "--release", "--examples"],
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print(f"BUILD FAILED for {target}:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example):
    """Run an example on QEMU via cargo run. Returns stdout+stderr."""
    rc, out, err = run_cmd(
        ["cargo", "run", "--target", target, "--release", "--example", example]
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"    cargo run failed (rc={rc}):", file=sys.stderr)
        print(combined, file=sys.stderr)
    return combined


def parse_text_size(output):
    """Parse .text size from size -A output."""
    for line in output.splitlines():
        if line.startswith(".text"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    return None


def get_text_size(target, example):
    """Get .text section size via cargo-size, falling back to arm-none-eabi-size."""
    # cargo-size wraps llvm-size from the toolchain
    try:
        rc, out, _ = run_cmd([
            "cargo", "size", "--release", "--target", target,
            "--example", example, "--", "-A",
        ])
        if rc == 0:
            size = parse_text_size(out)
            if size is not None:
                return size
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    cargo-size not available: {e}", file=sys.stderr)
    # Fallback: try arm-none-eabi-size directly on the ELF
    elf = f"target/{target}/release/examples/{example}"
    try:
        rc, out, _ = run_cmd(["arm-none-eabi-size", "-A", elf])
        if rc == 0:
            return parse_text_size(out)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"    arm-none-eabi-size not available: {e}", file=sys.stderr)
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
        if not build_examples(target):
            failures.append(f"Build failed: {target}")
            continue

        for example in EXAMPLES:
            key = (example, target)
            print(f"  Running {example} on {label}...", file=sys.stderr)
            try:
                output = run_qemu(target, example)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} on {label}")
                continue

            accepted = "ed25519 ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example)

            if not metric:
                print(f"    METRIC line missing", file=sys.stderr)
                failures.append(f"Missing METRIC: {example} on {label}")
            if text_size is None:
                print(f"    .text size unavailable", file=sys.stderr)
                failures.append(f"Missing .text size: {example} on {label}")

            results[key] = {
                "accepted": accepted,
                "stack": metric["stack"] if metric else None,
                "cycles": metric["cycles"] if metric else None,
                "text_size": text_size,
            }

            status = "ACCEPT" if accepted else "REJECT"
            print(f"    {status}", file=sys.stderr)
            if not accepted:
                failures.append(f"REJECT: {example} on {label}")

    # Generate markdown table
    backends = {"ed25519_u8": "u8", "ed25519_u32": "u32"}
    metrics = ["Stack (bytes)", "Cycles (k)", ".text (KiB)"]
    target_labels = [label for _, label in TARGETS]

    print()
    print(f"| Backend | Metric | {' | '.join(target_labels)} |")
    print(f"|---------|--------|{' | '.join(['------'] * len(TARGETS))} |")

    for example in EXAMPLES:
        backend = backends[example]
        for metric_name in metrics:
            cells = []
            for target, _ in TARGETS:
                r = results.get((example, target))
                if r is None:
                    cells.append("-")
                elif metric_name == "Stack (bytes)":
                    cells.append(str(r["stack"]) if r["stack"] is not None else "-")
                elif metric_name == "Cycles (k)":
                    cells.append(str(r["cycles"]) if r["cycles"] is not None else "-")
                elif metric_name == ".text (KiB)":
                    if r["text_size"] is not None:
                        cells.append(f"{r['text_size'] / 1024:.1f}")
                    else:
                        cells.append("-")
            print(f"| {backend} | {metric_name} | {' | '.join(cells)} |")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
