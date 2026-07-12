#!/bin/sh
# Panic-free audit: cross-build the audit staticlib and assert no panic
# call sites live inside ed25519_heapless code, including cases where
# ed25519_heapless functions get inlined into the `panic_audit__*`
# fixture bodies under fat LTO. Usage:
# check.sh [target-triple]  (defaults to thumbv7em-none-eabi; requires
# the rustup target and the llvm-tools-preview component).
#
# Scope: this crate's own code only, plus the fixture wrappers
# (`panic_audit__*`) — the wrappers are our fixture surface, and fat
# LTO routinely inlines callees into them, so panic sites that
# survive after inlining attribute to a fixture section rather than
# to an `ed25519_heapless::` section. Upstream (`hmac_sha512`, `sha2`,
# `digest`, `hybrid_array`, `modmath`, `fixed-bigint`, `subtle`,
# `zeroize`, core intrinsics) is assumed panic-free — that's an
# upstream concern, tracked upstream. Cross-boundary regressions are
# covered by higher-level integration tests, not this audit.
set -eu

TARGET="${1:-thumbv7em-none-eabi}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
OBJDUMP="$(rustc --print sysroot)/lib/rustlib/${HOST}/bin/llvm-objdump"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CT_VERIFY_DIR="${SCRIPT_DIR}/.."
# The audit lives in a nested workspace at `ct-verify/` — build from
# there so its pinned release profile applies (main crate's own
# `--release` builds don't inherit it).
TARGET_DIR="${CARGO_TARGET_DIR:-${CT_VERIFY_DIR}/target}"
ARCHIVE="${TARGET_DIR}/${TARGET}/release/libpanic_free_audit.a"

if [ ! -x "$OBJDUMP" ]; then
    echo "error: $OBJDUMP not found (install the llvm-tools-preview component)" >&2
    exit 2
fi

(cd "$CT_VERIFY_DIR" && cargo build --release -p panic-free-audit --features panic-handler --target "$TARGET")

# Walk callers of panic entry points. Each `R_* ... panic_bounds_check`
# / `panic_fmt` / `unwrap_failed` / `expect_failed` / slice-index /
# len-mismatch line in the disassembly is a call site; the
# `Disassembly of section` line above names the caller's symbol.
#
# Only report sections whose DEFINITION lives in ed25519_heapless (not
# upstream generics that got monomorphized in our compilation unit).
# In legacy Itanium mangling `_ZN<len><crate>` the first crate is
# always the definition site. In Rust v0 mangling `_R…Cs<hash>_<len>
# <crate>` the FIRST `Cs<hash>_<len><crate>` block after `_R` is the
# definition site (later `Cs` blocks are instantiation-site suffixes
# and don't identify code we own).
FOUND="$("$OBJDUMP" -d -r --demangle "$ARCHIVE" 2>/dev/null | awk '
    /^Disassembly of section/ { section = $NF; next }
    /^[[:space:]]+[0-9a-f]+:[[:space:]]+R_.*(panicking|slice_index_fail|len_mismatch_fail|slice_start_index|slice_end_index|unwrap_failed|expect_failed)/ {
        if (section ~ /panic_audit__/ ||
            section ~ /_ZN16ed25519_heapless/ ||
            section ~ /_R[^C]*Cs[^_]*_16ed25519_heapless/) {
            print section
        }
    }
' | sort -u)"

if [ -n "$FOUND" ]; then
    echo "panic paths reachable from ed25519_heapless code in ${ARCHIVE}:" >&2
    echo "$FOUND" >&2
    exit 1
fi
echo "OK: no panic paths in ed25519_heapless code for ${TARGET}"
