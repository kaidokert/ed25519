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
TIMEOUT = 120  # seconds per QEMU run


def run_cmd(args, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=TIMEOUT, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build_examples(target):
    """Build all examples for a target. Returns True on success."""
    rc, out, err = run_cmd(
        ["cargo", "build", "--target", target, "--release", "--examples"]
    )
    if rc != 0:
        print(f"BUILD FAILED for {target}:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example):
    """Run an example on QEMU via cargo run. Returns stdout."""
    rc, out, err = run_cmd(
        ["cargo", "run", "--target", target, "--release", "--example", example]
    )
    # QEMU output may be on stdout or stderr depending on semihosting
    return out + err


def get_text_size(target, example):
    """Get .text section size from the ELF using arm-none-eabi-size."""
    elf = f"target/{target}/release/examples/{example}"
    try:
        rc, out, _ = run_cmd(["arm-none-eabi-size", "-A", elf])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith(".text"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # Fallback: try llvm-size
    try:
        rc, out, _ = run_cmd(["llvm-size", "-A", elf])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith(".text"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
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
                print(f"    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} on {label}")
                continue

            accepted = "ed25519 ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example)

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
    print(f"|---------|--------|{'|'.join(['------|'] * len(TARGETS))}")

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
