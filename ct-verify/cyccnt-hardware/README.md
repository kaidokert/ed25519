# Ed25519/X25519 CYCCNT fixtures

Runs paired concrete secrets through the existing CT operation families on the
J-Trace STM32F407VG. Recorded trials use an interleaved ABBA order, execute
with interrupts masked, and read the Cortex-M DWT `CYCCNT`. Positive fixtures
require overlapping A/B ranges with a combined spread of at most 32 cycles;
the early-exit negative control must produce disjoint timing ranges. The
positive threshold is an absolute, fail-closed calibration from initial F407
measurements (7–20 cycles of spread over 26–477 million-cycle operations), and
all raw bounds are emitted for review.

The carrier uses `embedded-measure::PairedSuite` for DWT sampling, exact-path
warmups, paired ordering, policy evaluation, versioned reporting, and totals.
It emits lossless `EM_*` schema 1 records plus the legacy `CT_*` records while
host tooling migrates.

Build or run one carrier at a time from this directory:

```sh
cargo run --release --target thumbv7em-none-eabihf --features carrier-u32x8
cargo run --release --target thumbv7em-none-eabihf --features carrier-u32x16
cargo run --release --target thumbv7em-none-eabihf --features carrier-u8x32
```

This is a timing-regression layer, not a replacement for ctgrind or the
per-target ladder branch audit. Same-cycle divergent instruction paths remain
possible and are intended to be covered by a later J-Trace/ETM layer.
