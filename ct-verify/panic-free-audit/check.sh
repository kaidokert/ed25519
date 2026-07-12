#!/bin/sh
# Panic-free audit: cross-build the audit staticlib and assert no panic
# call sites live inside `ed25519_heapless::` code. Usage:
# check.sh [target-triple]  (defaults to thumbv7em-none-eabi; requires
# the rustup target and the llvm-tools-preview component).
#
# Scope: this crate's own code only. Upstream (`hmac_sha512`, `sha2`,
# `digest`, `hybrid_array`, `modmath`, `fixed-bigint`, `subtle`,
# `zeroize`, core intrinsics) is assumed panic-free — that's an
# upstream concern, tracked upstream. Cross-boundary regressions get
# caught by the RFC 8032 integration tests run under ctgrind, not
# here.
set -eu

TARGET="${1:-thumbv7em-none-eabi}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
OBJDUMP="$(rustc --print sysroot)/lib/rustlib/${HOST}/bin/llvm-objdump"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
ARCHIVE="${TARGET_DIR}/${TARGET}/release/libpanic_free_audit.a"

if [ ! -x "$OBJDUMP" ]; then
    echo "error: $OBJDUMP not found (install the llvm-tools-preview component)" >&2
    exit 2
fi

cargo build --release -p panic-free-audit --features panic-handler --target "$TARGET"

# Walk callers of panic entry points. Each `R_ARM_THM_CALL ...
# panic_bounds_check` / `panic_fmt` / slice-index / len-mismatch line
# in the disassembly is a call site; the `Disassembly of section` line
# above names the caller's symbol. We only care about callers that
# demangle into ed25519_heapless code — anything else is out of scope.
FOUND="$("$OBJDUMP" -d -r --demangle "$ARCHIVE" 2>/dev/null | awk '
    /^Disassembly of section/ { section = $NF; next }
    /^[[:space:]]+[0-9a-f]+:[[:space:]]+R_.*(panicking|slice_index_fail|len_mismatch_fail|slice_start_index|slice_end_index)/ {
        if (section ~ /ed25519_heapless/) print section
    }
' | sort -u)"

if [ -n "$FOUND" ]; then
    echo "panic paths reachable from ed25519_heapless code in ${ARCHIVE}:" >&2
    echo "$FOUND" >&2
    exit 1
fi
echo "OK: no panic paths in ed25519_heapless code for ${TARGET}"
