#!/usr/bin/env python3
"""Build and run ed25519 + x25519 examples on QEMU for all Cortex-M targets.

For each (algo, backend) pair the suite runs two variants: a `baseline`
build (where the cryptographic core is replaced by a do-nothing stub) and
a `verify` build (the real impl). The reported metrics are
verify-minus-baseline deltas, isolating the cost of the cryptographic
operation from the surrounding harness.
"""

import json
import re
import subprocess
import sys

# (example, algo label, backend label, variant label, cargo --features list)
EXAMPLES = [
    ("ed25519_u8",  "ed25519", "u8",  "baseline", ["baseline"]),
    ("ed25519_u8",  "ed25519", "u8",  "verify",   []),
    ("ed25519_u32", "ed25519", "u32", "baseline", ["baseline"]),
    ("ed25519_u32", "ed25519", "u32", "verify",   []),
    ("x25519_u8",   "x25519",  "u8",  "baseline", ["baseline"]),
    ("x25519_u8",   "x25519",  "u8",  "verify",   []),
    ("x25519_u32",  "x25519",  "u32", "baseline", ["baseline"]),
    ("x25519_u32",  "x25519",  "u32", "verify",   []),
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
    """Build all examples for a target/feature set. Returns True on success."""
    args = ["cargo", "build", "--target", target, "--release", "--examples"]
    if features:
        args.extend(["--features", ",".join(features)])
    try:
        rc, _out, err = run_cmd(args, timeout=TIMEOUT_BUILD)
    except subprocess.TimeoutExpired:
        print(
            f"BUILD TIMEOUT for {target} (features={features}) after {TIMEOUT_BUILD}s",
            file=sys.stderr,
        )
        return False
    if rc != 0:
        print(f"BUILD FAILED for {target} (features={features}):", file=sys.stderr)
        print(err, file=sys.stderr)
        return False
    return True


def run_qemu(target, example, features):
    """Run an example on QEMU via cargo run. Returns stdout+stderr."""
    args = ["cargo", "run", "--target", target, "--release", "--example", example]
    if features:
        args.extend(["--features", ",".join(features)])
    rc, out, err = run_cmd(args)
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
            json_line = out.strip().split("\n")[-1]
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
        r"METRIC stack:(\d+) cycles:(\d+) target:(\S+)"
        r"(?: algo:(\S+))? backend:(\S+)",
        output,
    )
    if m:
        return {
            "stack": int(m.group(1)),
            "cycles": int(m.group(2)),
            "target": m.group(3),
            "algo": m.group(4),
            "backend": m.group(5),
        }
    return None


def delta(verify_row, baseline_row, key, formatter=str):
    v = verify_row.get(key)
    b = baseline_row.get(key)
    if v is None or b is None:
        return "-"
    return formatter(v - b)


def main():
    # results indexed by (algo, backend, variant, target)
    results = {}
    failures = []

    for target, label in TARGETS:
        print(f"Building for {target}...", file=sys.stderr)

        # Build once per distinct feature set (avoids rebuilding examples
        # multiple times for each backend within the same feature set).
        feature_groups = {}
        for _, _, _, variant, features in EXAMPLES:
            feature_groups.setdefault(tuple(features), []).append(variant)
        build_ok = {}
        for feat_key, variants in feature_groups.items():
            ok = build_examples(target, list(feat_key))
            build_ok[feat_key] = ok
            if not ok:
                joined = ", ".join(sorted(set(variants)))
                failures.append(f"Build failed: {target} ({joined})")

        for example, algo, backend, variant, features in EXAMPLES:
            feat_key = tuple(features)
            if not build_ok.get(feat_key, False):
                continue
            key = (algo, backend, variant, target)
            print(f"  Running {example} [{variant}] on {label}...", file=sys.stderr)
            try:
                output = run_qemu(target, example, features)
            except subprocess.TimeoutExpired:
                print("    TIMEOUT", file=sys.stderr)
                failures.append(f"Timeout: {example} [{variant}] on {label}")
                continue

            accepted = f"{algo} ACCEPT" in output
            metric = parse_metric(output)
            text_size = get_text_size(target, example, features)

            if not metric:
                print("    METRIC line missing", file=sys.stderr)
                failures.append(f"Missing METRIC: {example} [{variant}] on {label}")
            else:
                # Defensive: confirm the METRIC line was emitted by the binary
                # we believe we just ran. Mislabeled or stale output would
                # otherwise be silently attributed to the wrong row.
                expected_target_cfg = target.split("-")[0]
                if metric.get("target") != expected_target_cfg:
                    print(
                        f"    METRIC target mismatch (got {metric.get('target')},"
                        f" expected {expected_target_cfg})",
                        file=sys.stderr,
                    )
                    failures.append(
                        f"Mismatched METRIC target: {example} [{variant}] on {label}"
                    )
                    metric = None
                elif metric.get("backend") != backend:
                    print(
                        f"    METRIC backend mismatch (got {metric.get('backend')},"
                        f" expected {backend})",
                        file=sys.stderr,
                    )
                    failures.append(
                        f"Mismatched METRIC backend: {example} [{variant}] on {label}"
                    )
                    metric = None
                elif metric.get("algo") not in (None, algo):
                    print(
                        f"    METRIC algo mismatch (got {metric.get('algo')},"
                        f" expected {algo})",
                        file=sys.stderr,
                    )
                    failures.append(
                        f"Mismatched METRIC algo: {example} [{variant}] on {label}"
                    )
                    metric = None
            if text_size is None:
                print("    .text size unavailable", file=sys.stderr)
                failures.append(f"Missing .text size: {example} [{variant}] on {label}")

            results[key] = {
                "accepted": accepted,
                "stack": metric["stack"] if metric else None,
                "cycles": metric["cycles"] if metric else None,
                "text_size": text_size,
            }

            status = "ACCEPT" if accepted else "REJECT"
            print(f"    {status}", file=sys.stderr)
            if not accepted:
                failures.append(f"REJECT: {example} [{variant}] on {label}")

    # Distinct (algo, backend) pairs in the order they first appear
    seen = []
    for _, algo, backend, _, _ in EXAMPLES:
        if (algo, backend) not in seen:
            seen.append((algo, backend))

    print()
    print(
        "Metrics below are verify-minus-baseline deltas: the incremental flash,"
        " stack, and approximate cycle cost of the cryptographic operation."
    )
    print()
    print("| Target | Algo | Backend | .text (KiB) | Stack (bytes) | Approx cycles (k) |")
    print("|--------|------|---------|-------------|---------------|-------------------|")
    for target, label in TARGETS:
        for algo, backend in seen:
            verify_row = results.get((algo, backend, "verify", target))
            baseline_row = results.get((algo, backend, "baseline", target))
            if verify_row is None or baseline_row is None:
                print(f"| {label} | {algo} | {backend} | - | - | - |")
                continue
            dtext = delta(
                verify_row, baseline_row, "text_size",
                formatter=lambda v: f"{v / 1024:.1f}",
            )
            dstack = delta(verify_row, baseline_row, "stack")
            # Rust test_fixture already divides cycle counts by 1000 before
            # emitting the METRIC line, so verify-minus-baseline is already
            # expressed in thousands of cycles — matching the "(k)" header.
            dcycles = delta(verify_row, baseline_row, "cycles")
            print(f"| {label} | {algo} | {backend} | {dtext} | {dstack} | {dcycles} |")

    print()
    print(
        "Approx cycles are derived from the demo harness counters and should"
        " be treated as a rough instruction-cost proxy, not a precise benchmark."
    )

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
