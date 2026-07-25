# ct-verify

Constant-time verification harnesses for `ed25519_heapless`'s
secret-touching surface. Nested workspace with its own pinned release
profile so the harness inspects deployment-shaped code without
leaking the pin into the main crate's own `--release` builds.

Four members, each catching what the others can't:

- **`panic-free-audit`** — cross-target staticlib. Wraps
  `SigningKey::from_seed`, `sign`, `verify`, `x25519`, and
  `x25519_base` as `#[no_mangle] pub extern "C"` fixtures with
  `black_box` at every boundary. `check.sh` cross-builds for
  `thumbv7em-none-eabi` and `riscv32imc-unknown-none-elf`,
  disassembles the archive, and asserts no `core::panicking` /
  `slice_index_fail` / `len_mismatch_fail` / `unwrap_failed` /
  `expect_failed` call site lives inside `ed25519_heapless`-defined
  code. A reachable panic in the CT surface is both a DoS edge and
  a timing oracle — the format path's cost depends on the values.
  A two-pass run also builds with `--features neg-controls` and
  asserts the deliberately-panicky `panic_audit__neg__*` fixtures
  trip; a silent pass on a negative means the walker itself is
  broken.

- **`ct-ctgrind`** — Linux-only Valgrind driver. Runs each fixture
  under memcheck with secret operands (seeds, scalars) tagged
  `MAKE_MEM_UNDEFINED` via crabgrind. Any conditional jump or memory
  access derived from the tainted bytes — including inside inlined
  upstream primitives — trips a memcheck error. Positive fixtures at
  three carriers to cover the shapes downstream actually deploys:
  `FixedUInt<u32, 8, Ct>` (256-bit minimum, one bit above the field
  prime); `FixedUInt<u32, 16, Ct>` (512-bit, matches the
  `cortex_m_demo` and `riscv_demo` u32 examples); `FixedUInt<u8, 32,
  Ct>` (256-bit u8 limbs, matches `avr_demo` and the cortex_m u8
  example). Different limb widths and counts monomorphize to
  materially different loop layouts, so a leak visible in only one
  wouldn't be caught by fixturing another. Negative controls
  (`nct_fix__neg__branch_on_secret`, `nct_fix__neg__index_by_secret`,
  `nct_fix__neg__equality_on_secret`) MUST trip; the driver
  fails-closed on both a positive that tripped and a negative that
  didn't.

- **`ladder-branches`** — narrow calibrated per-ISA branch-count
  check on the two CT scalar-mul ladders (`montgomery_ladder` in
  x25519, `scalar_mult_ct` in strict_sign). Neither is literally
  branch-free — both contain a public-bounded loop-control branch —
  so the right calibration is a counted per-ISA allowance, not a
  whole-symbol skip that would vacuously pass a regression adding a
  secret branch. Fails closed if a ladder symbol isn't present in
  the archive (fat LTO can inline it away, at which point the
  structural claim isn't observable). Supplements ctgrind rather
  than replacing it: ctgrind proves the branches are actually
  secret-independent under runtime taint; this check proves the
  emitted structure stays what we calibrated.

- **`cyccnt-hardware`** — paired-secret timing regression gate for the
  J-Trace STM32F407VG. It runs key derivation, signing, X25519, and
  X25519-base across the same `u32x8`, `u32x16`, and `u8x32` carrier
  shapes used by ctgrind. Recorded trials use balanced ABBA ordering,
  mask interrupts, and read DWT `CYCCNT`. Two layers gate: on-device, a
  positive fixture whose A/B cycle ranges spread past 32 or fail to
  overlap reports `status:FAIL` and fails the campaign; off-device, a
  Welch t-test (`gate = true`) requires the positive classes to stay under
  the threshold and the early-exit negative control to exceed it — so the
  statistical layer catches a systematic bias that stays under the 32-cycle
  spread bound, and the control proves the harness can still see a leak.
  This adds physical target evidence but does not replace taint or
  instruction-flow analysis: distinct paths can have equal cycle counts.

## Scope boundary

The harnesses audit `ed25519_heapless`-defined code only. Upstream
crates (`hmac_sha512`, `sha2`, `digest`, `hybrid_array`, `modmath`,
`fixed-bigint`, `const-num-traits`, `subtle`, `zeroize`, core
intrinsics) are assumed CT / panic-free — that's an upstream
concern, tracked upstream. If a downstream taint run flags a leak
that traces into an upstream helper, we file against upstream and
retest. This crate's harness doesn't re-verify upstream primitives.

## Documented limitations

- **Symbol attribution boundary in the panic-free audit.** The
  walker flags call sites where the CALLER's section demangles into
  `ed25519_heapless::` (Rust v0 mangling: first `Cs<hash>_<len>
  <crate>` after `_R`; legacy Itanium: `_ZN<len><crate>` prefix).
  Panics reached only via an upstream helper shim (e.g.
  `slice.copy_from_slice(other)` → `core::slice::copy_from_slice_impl`
  → `len_mismatch_fail`) attribute to the shim, not to our caller,
  and don't trip this gate. The ctgrind taint pass IS transitive by
  construction and covers this shape at runtime on Linux hosts;
  Thumb / RISC-V miss it.

- **Cache / speculation side channels are out of scope.** Both taint
  and asm-grep see only architectural behaviour. A leak that lives
  entirely in the microarchitecture (cache-line, branch predictor,
  speculative fetch) needs different tooling.

- **Thumb IT-block predication has no bare-metal taint tool** in the
  ecosystem today; `cargo-checkct` is the documented eventual answer
  and remains deferred. Coverage on Thumb rests on the ladder-branch
  calibration plus the host-arch ctgrind run.

- **Ladder-branches counts CONDITIONAL branches; it doesn't inspect
  what they branch on.** The calibration prevents a regression from
  silently adding a fifth branch, but the semantic claim that all
  N branches are public-bounded loop-control rests on the ctgrind
  taint pass.

- **panic-free-audit and ladder-branches instantiate at
  `FixedUInt<u32, 8, Ct>` only.** That's the minimum-size backend
  (256 bits); the deployed 512-bit and u8-limb shapes are covered
  by ctgrind at runtime instead. The structural argument for
  extrapolating "no reachable panic on `<u32, 8>`" to other widths
  rests on ed25519_heapless being generic over `T` with no
  width-conditional code path.

## Running

Every check runs from the `ct-verify/` directory to pick up the
pinned release profile. Assumes the `llvm-tools-preview` rustup
component is installed.

```
# Panic-free audit + neg-control self-test
cargo krabi-caliper panic-audit --package panic-free-audit \
  --target thumbv7em-none-eabi --features panic-handler \
  --negative-features neg-controls \
  --owned-symbol 'panic_audit__|ed25519_heapless::' \
  --expect-negative panic_audit__neg__bounds_check \
  --expect-negative panic_audit__neg__unwrap \
  --expect-negative panic_audit__neg__expect

# Per-ISA ladder-branch calibration (reuses the same archive)
cargo build --release -p ladder-branches
./target/release/ladder-branches thumbv7em-none-eabi
./target/release/ladder-branches riscv32imc-unknown-none-elf

# ctgrind runtime taint (Linux only; install `valgrind` first)
cargo build --release -p ct-ctgrind
cargo krabi-caliper ctgrind target/release/ct-ctgrind

# Physical STM32F407 CYCCNT gate (run each carrier separately)
cargo run --release --target thumbv7em-none-eabihf \
    -p cyccnt-hardware --features carrier-u32x8
```

CI runs all three in `.github/workflows/ct-verify.yml` on every
push and pull request.
