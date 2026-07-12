#!/bin/sh
# Narrow-scope ladder-branch calibration.
#
# ed25519_heapless has two secret-scalar consumers on the CT path:
#   - `x25519::montgomery_ladder`      — the X25519 always-swap ladder.
#   - `strict_sign::scalar_mult_ct`    — the Ed25519 sign-side scalar
#                                        multiplication.
#
# Each is *not* literally branch-free: both contain public-bounded
# loop-control branches (fixed-iteration count over T::BITS / the
# clamped scalar shape) that are invariant in the secret. The
# per-bit selection uses branchless `conditional_select`. So the
# right calibration is a **counted per-ISA branch allowance**, not a
# whole-symbol skip — whole-symbol skip would vacuously pass a
# regression that added a secret branch.
#
# Fail closed if either ladder symbol isn't present in the archive —
# fat LTO can inline the ladder into its caller, at which point the
# structural claim isn't observable and we should say so loudly.
#
# This is a supplement to the ctgrind taint gate, not a substitute.
# ctgrind proves the branches are actually secret-independent under
# runtime taint; asm-grep proves the *structure* is what we expect.
set -eu

TARGET="${1:-thumbv7em-none-eabi}"
HOST="$(rustc -vV | sed -n 's/^host: //p')"
OBJDUMP="$(rustc --print sysroot)/lib/rustlib/${HOST}/bin/llvm-objdump"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CT_VERIFY_DIR="${SCRIPT_DIR}/.."
TARGET_DIR="${CARGO_TARGET_DIR:-${CT_VERIFY_DIR}/target}"
ARCHIVE="${TARGET_DIR}/${TARGET}/release/libpanic_free_audit.a"

if [ ! -x "$OBJDUMP" ]; then
    echo "error: $OBJDUMP not found (install the llvm-tools-preview component)" >&2
    exit 2
fi

# Per-ISA conditional-branch mnemonic regex + calibrated counts.
# The counts are *measured* against a clean build; a regression that
# adds a secret-dependent branch bumps the count and fails the check.
# A refactor that legitimately changes the loop shape re-calibrates
# these numbers.
case "$TARGET" in
    thumbv7em-none-eabi|thumbv7m-none-eabi|thumbv6m-none-eabi)
        # b<cc>[.n|.w], cbz/cbnz, tbz/tbnz. Unconditional `b`, `bl`,
        # `blx`, `bx` are excluded.
        BRANCH_RE='(\<b(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.[nw])?\>|\<cbn?z\>|\<tbn?z\>)'
        EXPECTED_ML=1
        EXPECTED_SM=1
        ;;
    riscv32imc-unknown-none-elf|riscv32imac-unknown-none-elf)
        # Real: beq/bne/blt/bge/bltu/bgeu. Pseudo: bgtz/bltz/bnez/
        # beqz/bgez/blez/bgt/ble/bgtu/bleu. Compressed: c.beqz/c.bnez.
        BRANCH_RE='(\<b(eq|ne|lt|ge|ltu|geu|gtz|ltz|nez|eqz|gez|lez|gt|le|gtu|leu)\>|\<c\.b(eqz|nez)\>)'
        EXPECTED_ML=1
        EXPECTED_SM=2
        ;;
    *)
        echo "error: unknown target $TARGET (add per-ISA calibration to check.sh)" >&2
        exit 2
        ;;
esac

# Build the archive if it isn't already there. Same nested-workspace
# invocation as panic-free-audit's check.sh, so a hot cache is hit
# when the panic-free step ran first.
if [ ! -f "$ARCHIVE" ]; then
    (cd "$CT_VERIFY_DIR" && cargo build --release -p panic-free-audit --features panic-handler --target "$TARGET")
fi

DISASM="$("$OBJDUMP" -d --demangle "$ARCHIVE" 2>/dev/null)"

find_section() {
    printf '%s\n' "$DISASM" | \
        awk -v pat="$1" '/^Disassembly of section/ && index($0, pat) { print $NF; exit }'
}

count_branches_in_section() {
    printf '%s\n' "$DISASM" | \
        awk -v s="$1" 'BEGIN{f=0}
            $0 == "Disassembly of section " s { f=1; next }
            /^Disassembly of section/ { f=0 }
            f' | \
        grep -cE "^[[:space:]]+[0-9a-f]+:.*${BRANCH_RE}" || true
}

FAIL=0
check_ladder() {
    NAME="$1"
    PATTERN="$2"
    EXPECTED="$3"
    SECTION="$(find_section "$PATTERN")"
    if [ -z "$SECTION" ]; then
        echo "  FAIL: $NAME — section not found (LTO inlined into caller?)"
        FAIL=1
        return
    fi
    COUNT="$(count_branches_in_section "$SECTION")"
    if [ "$COUNT" -ne "$EXPECTED" ]; then
        echo "  FAIL: $NAME — expected $EXPECTED conditional branch(es), found $COUNT"
        printf '%s\n' "$DISASM" | \
            awk -v s="$SECTION" 'BEGIN{f=0}
                $0 == "Disassembly of section " s { f=1; next }
                /^Disassembly of section/ { f=0 }
                f' | \
            grep -E "^[[:space:]]+[0-9a-f]+:.*${BRANCH_RE}" >&2 || true
        FAIL=1
        return
    fi
    echo "  OK: $NAME — $COUNT conditional branch(es) matches calibration"
}

echo "[ladder-branches] $TARGET"
check_ladder "x25519::montgomery_ladder" "montgomery_ladder" "$EXPECTED_ML"
check_ladder "strict_sign::scalar_mult_ct" "scalar_mult_ct" "$EXPECTED_SM"

exit "$FAIL"
