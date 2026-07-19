# Cortex-M footprint harness

The shared Rust runner owns the QEMU M0/M3/M4 matrix, semihosting capture,
ELF accounting, deadlines, and reports:

```sh
cargo krabi-caliper run ed25519-cortex-m0
cargo krabi-caliper run ed25519-cortex-m3
cargo krabi-caliper run ed25519-cortex-m4
cargo krabi-caliper run ed25519-jtrace-f407
```

Run these commands in this directory after installing `krabi-caliper` with
its `cli` feature. Configuration lives in `krabi-caliper.toml`.

The J-Trace campaign reuses the same case set as QEMU, adding the board feature
at profile level and using RTT on the STM32F407VG. It finishes in a `NOP` loop
so an attached debugger can halt it reliably. A focused parity run is:

```sh
cargo krabi-caliper run ed25519-jtrace-f407 \
  --case ed25519-u32-baseline --case ed25519-u32-verify
```

The report artifacts retain the complete `probe-rs run` command and output.
After `EM_OUTCOME`, the runner interrupts `probe-rs` gracefully so it can
release the J-Trace USB transport before the next case.

The shared `krabi-caliper` lifecycle adapter emits a versioned `EM_STACK`
record and canonical `EM_MEASUREMENT` records named `systick` and `dwt`.
The stack probe uses cortex-m-rt's `_stack_end` linker symbol as its lower
bound, keeping RTT's static control block and channel buffer outside the
painted stack region. The 32-bit DWT result is valid for measured intervals
shorter than 2^32 core cycles.
