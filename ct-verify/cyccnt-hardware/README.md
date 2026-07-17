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

Run the complete declarative hardware gate from this directory:

```sh
cargo embedded-measure run ed25519-ct-jtrace-f407
```

Repeatable `--case u32x8`, `--case u32x16`, and `--case u8x32` options select
individual carriers. The runner owns build features, probe selection,
deadlines, RTT completion, protocol validation, and retained evidence under
`target/embedded-measure/ed25519-ct-jtrace-f407/`.

The migration campaign preserved the existing fail-closed policy and found:

- `u32x8`: all five fixtures passed; positive spreads were 6–15 cycles.
- `u32x16`: all five fixtures passed; positive spreads were 7–18 cycles.
- `u8x32`: four passed and `sign` failed because its A/B ranges were disjoint,
  despite only 21 cycles of combined spread. The other positive fixtures had
  overlapping ranges and 8–17 cycles of spread.

An earlier run that allowed each interval to begin at an arbitrary global
CYCCNT phase produced different marginal overlap outcomes. The shared Cortex-M
adapter now anchors CYCCNT at zero immediately before every interrupt-free
measured region, removing rollover phase as a source of classification noise.

These are hardware gate findings rather than runner failures; the aggregate
campaign exits unsuccessfully until they are investigated or fixed.

This is a timing-regression layer, not a replacement for ctgrind or the
per-target ladder branch audit. Same-cycle divergent instruction paths remain
possible and are intended to be covered by a later J-Trace/ETM layer.
