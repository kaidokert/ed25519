# RISC-V footprint harness

Run the complete SiFive-E QEMU matrix with:

```sh
cargo krabi-caliper run ed25519-riscv32
```

The firmware emits the shared `EM_*` protocol over UART. Because this machine
has no firmware exit mechanism, the Rust runner stops QEMU after the final
`EM_OUTCOME` record. It also retains each ELF, accounts for flash/static RAM,
and reports verify-minus-baseline flash, stack, and cycle deltas.
