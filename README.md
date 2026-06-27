### ed25519 heapless fork

[![crate](https://img.shields.io/crates/v/ed25519_heapless.svg)](https://crates.io/crates/ed25519_heapless)
[![documentation](https://docs.rs/ed25519_heapless/badge.svg)](https://docs.rs/ed25519_heapless/)
[![Rust](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml)
[![AVR](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml)

This is a fork of the `ed25519` crate, ported to microcontrollers. Signature verification is implemented through generic traits, currently using [fixed-bigint](https://crates.io/crates/fixed-bigint) as the backend. It's tested on 8-bit AVR, Cortex-M and RISC-V.

The implementation balances code size, stack usage and execution speed rather than optimizing purely for speed. It only does signature verification right now (e.g., bootloaders), as private key handling requires constant-time operations, a trustworthy random source and secure storage for the private key.

#### Resource usage (as of version 0.0.3)

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| AVR ATmega2560 | u8×32 | 16.5 | 2669 |
| Cortex-M0 | u8×32 | 10.3 | 2656 |
| Cortex-M3 | u8×32 | 10.4 | 2564 |
| Cortex-M0 | u32×16 | 10.3 | 5092 |
| Cortex-M3 | u32×16 | 10.3 | 4996 |
| RV32IMAC | u8×32 | 12.9 | 2522 |
| RV32IMAC | u32×16 | 12.4 | 4932 |



The .text values represent the incremental flash used by signature verification itself, measured as verify-minus-baseline in the demo harnesses.
The stack values represent the corresponding incremental stack usage attributable to signature verification, not the total stack footprint of the whole binary.
