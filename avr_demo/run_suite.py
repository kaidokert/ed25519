#!/usr/bin/env python3
"""Build and run ed25519 verification on simavr for AVR ATmega2560.

Generates a markdown metrics table from the results.
"""

import re
import subprocess
import sys

EXAMPLE = "test_verify"
TIMEOUT = 120  # seconds per simavr run


def run_cmd(args, **kwargs):
    """Run a command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=TIMEOUT, **kwargs
    )
    return result.returncode, result.stdout, result.stderr


def build():
    """Build the example. Returns True on success."""
    rc, _out, err = run_cmd(
        ["cargo", "build", "--release", "--example", EXAMPLE]
    )
    if rc != 0:
        print("BUILD FAILED:", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_simavr():
    """Run the example via cargo run (uses .cargo/config.toml runner). Returns stdout+stderr."""
    _rc, out, err = run_cmd(
        ["cargo", "run", "--release", "--example", EXAMPLE]
    )
    return out + err


def parse_text_size(output):
    """Parse .text size from size -A output."""
    for line in output.splitlines():
        if line.startswith(".text"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    return None


def get_text_size():
    """Get .text section size via cargo-size, falling back to avr-size."""
    # cargo-size wraps llvm-size from the toolchain
    try:
        rc, out, _ = run_cmd([
            "cargo", "size", "--release", "--example", EXAMPLE, "--", "-A",
        ])
        if rc == 0:
            size = parse_text_size(out)
            if size is not None:
                return size
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # Fallback: try avr-size directly on the ELF
    elf = f"target/avr-none/release/examples/{EXAMPLE}.elf"
    try:
        rc, out, _ = run_cmd(["avr-size", "-A", elf])
        if rc == 0:
            return parse_text_size(out)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def parse_output(output):
    """Parse AVR serial output. Returns dict with accept, stack, time_ms, ticks."""
    result = {"accepted": False, "stack": None, "time_ms": None, "ticks": None}

    result["accepted"] = "ACCEPT" in output

    m = re.search(r"Time:\s*(\d+)\s*ms\s*\((\d+)\s*ticks\)", output)
    if m:
        result["time_ms"] = int(m.group(1))
        result["ticks"] = int(m.group(2))

    m = re.search(r"Max stack usage:\s*(\d+)\s*bytes", output)
    if m:
        result["stack"] = int(m.group(1))

    return result


def main():
    print("Building for AVR...", file=sys.stderr)
    if not build():
        return 1

    print("  Running test_verify on simavr...", file=sys.stderr)
    try:
        output = run_simavr()
    except subprocess.TimeoutExpired:
        print("    TIMEOUT", file=sys.stderr)
        return 1

    result = parse_output(output)
    text_size = get_text_size()

    status = "ACCEPT" if result["accepted"] else "REJECT"
    print(f"    {status}", file=sys.stderr)

    # Generate markdown table
    stack = str(result["stack"]) if result["stack"] is not None else "-"
    time_ms = str(result["time_ms"]) if result["time_ms"] is not None else "-"
    ticks = str(result["ticks"]) if result["ticks"] is not None else "-"
    text_kib = f"{text_size / 1024:.1f}" if text_size is not None else "-"

    print()
    print("| Target | Backend | .text (KiB) | Stack (bytes) | Time (ms) | Ticks |")
    print("|--------|---------|-------------|---------------|-----------|-------|")
    print(f"| ATmega2560 | u8 | {text_kib} | {stack} | {time_ms} | {ticks} |")

    if not result["accepted"]:
        print("\nFailure: signature REJECT", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
