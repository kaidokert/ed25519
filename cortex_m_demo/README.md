# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, and reports:

```sh
cargo embedded-measure run ed25519-cortex-m0
cargo embedded-measure run ed25519-cortex-m3
cargo embedded-measure run ed25519-cortex-m4
```

Run these commands in this directory after installing `embedded-measure` with
its `cli` feature. Configuration lives in `embedded-measure.toml`.

The `ed25519_u32` workload can also run on the J-Trace reference board's
STM32F407VG. It uses RTT and finishes in a `NOP` loop so an attached debugger
can halt it reliably:

```sh
cargo build --release --target thumbv7em-none-eabihf \
  --example ed25519_u32 --features jtrace-f407
probe-rs run --chip STM32F407VGTx --protocol swd \
  --probe 1366:1020:001224000224 \
  target/thumbv7em-none-eabihf/release/examples/ed25519_u32
```

The hardware `METRIC` line includes the stack high-water mark. The shared
`embedded-measure` stack probe uses cortex-m-rt's `_stack_end` linker symbol as
its lower bound, keeping RTT's static control block and channel buffer outside
the painted stack region.
Stack results are emitted as versioned `EM_STACK` records; the legacy
`METRIC stack:` field remains during parser migration.

Hardware metrics also include raw `dwt_cycles` from the Cortex-M DWT
`CYCCNT` and raw `systick_cycles` for direct comparison. The existing
`cycles` field remains the SysTick count divided by 1,000 for compatibility
with the QEMU suite, where `CYCCNT` is unavailable. The 32-bit DWT result is
valid for measured intervals shorter than 2^32 core cycles.
