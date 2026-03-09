#!/usr/bin/env python3
"""Build and run ed25519 verification on QEMU for RISC-V sifive_e.

Generates a markdown metrics table from the results.
"""

import json
import re
import subprocess
import sys

EXAMPLES = ["ed25519_u8", "ed25519_u32"]
TIMEOUT_RUN = 120  # seconds per QEMU run
TIMEOUT_BUILD = 600  # seconds for cargo build


def run_cmd(args, timeout=TIMEOUT_RUN, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build():
    """Build all examples. Returns True on success."""
    rc, _out, err = run_cmd(
        ["cargo", "build", "--release", "--examples"],
        timeout=TIMEOUT_BUILD,
    )
    if rc != 0:
        print("BUILD FAILED:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(example):
    """Run an example via cargo run (uses .cargo/config.toml runner). Returns stdout+stderr."""
    rc, out, err = run_cmd(
        ["cargo", "run", "--release", "--example", example]
    )
    combined = out + err
    if rc != 0 and "ACCEPT" not in combined and "REJECT" not in combined:
        print(f"    cargo run failed (rc={rc}):", file=sys.stderr)
        print(combined, file=sys.stderr)
    return combined


def get_text_size(example):
    """Get .text section size via cargo-bloat JSON output."""
    try:
        rc, out, err = run_cmd([
            "cargo", "bloat", "--release",
            "--example", example, "--message-format=json",
        ], timeout=TIMEOUT_BUILD)
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


def main():
    results = {}  # example -> {accepted, stack, cycles, text_size}
    failures = []

    print("Building for RISC-V...", file=sys.stderr)
    if not build():
        return 1

    for example in EXAMPLES:
        backend = example.replace("ed25519_", "")
        print(f"  Running {example} on QEMU sifive_e...", file=sys.stderr)
        try:
            output = run_qemu(example)
        except subprocess.TimeoutExpired:
            print("    TIMEOUT", file=sys.stderr)
            failures.append(f"Timeout: {example}")
            continue

        accepted = "ed25519 ACCEPT" in output
        metric = parse_metric(output)
        text_size = get_text_size(example)

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

        results[example] = {
            "accepted": accepted,
            "stack": metric["stack"] if metric else None,
            "cycles": metric["cycles"] if metric else None,
            "text_size": text_size,
        }

    # Generate markdown table
    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Cycles (k) |")
    print("|--------|---------|-------------|---------------|------------|")

    for example in EXAMPLES:
        backend = example.replace("ed25519_", "")
        r = results.get(example)
        if r is None:
            print(f"| sifive_e (RV32) | {backend} | - | - | - |")
            continue
        stack = str(r["stack"]) if r["stack"] is not None else "-"
        cycles = str(r["cycles"]) if r["cycles"] is not None else "-"
        text_kib = f"{r['text_size'] / 1024:.1f}" if r["text_size"] is not None else "-"
        print(f"| sifive_e (RV32) | {backend} | {text_kib} | {stack} | {cycles} |")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
