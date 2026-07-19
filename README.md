### ed25519 heapless fork

[![crate](https://img.shields.io/crates/v/ed25519_heapless.svg)](https://crates.io/crates/ed25519_heapless)
[![documentation](https://docs.rs/ed25519_heapless/badge.svg)](https://docs.rs/ed25519_heapless/)
[![Rust](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml)
[![AVR](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml)

This is a fork of the `ed25519` crate, ported to microcontrollers. It is generic over the bignum backend: bring your own by implementing the trait bundle, or use [fixed-bigint](https://crates.io/crates/fixed-bigint) (the reference backend, with both fixed-width and runtime-length carriers). Tested on 8-bit AVR, Cortex-M and RISC-V.

The implementation balances code size, stack usage and execution speed rather than optimizing purely for speed. Alongside signature verification (e.g., bootloaders), it provides Ed25519 signing and X25519 key exchange — with optional scalar/coordinate blinding — on constant-time field arithmetic. Callers remain responsible for a trustworthy random source and secure private-key storage.

#### Resource usage — signature verification (measured at v0.0.3)

These figures are for the verify path only and predate the sign / X25519 work; they are indicative rather than current.

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
