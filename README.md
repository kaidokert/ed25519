### ed25519 heapless fork

[![Rust](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml)
[![AVR](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml)

This is a fork of the `ed25519` crate, ported to microcontrollers. Signature verification is implemented through generic traits, currently using [fixed-bigint](https://crates.io/crates/fixed-bigint) as the backend. It's tested on 8-bit AVR, Cortex-M and RISC-V.

The implementation balances code size, stack usage and execution speed rather than optimizing purely for speed. It only does signature verification right now (e.g., bootloaders), as private key handling requires constant-time operations, a trustworthy random source and secure storage for the private key.

#### Resource usage (as of version 0.0.1)

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| AVR ATmega2560 | u8×32 | 20.1 | 3062 |
| Cortex-M0 | u8×32 | 15.9 | 3348 |
| Cortex-M3 | u8×32 | 15.2 | 3252 |
| Cortex-M0 | u32×16 | 16.2 | 6092 |
| Cortex-M3 | u32×16 | 15.2 | 6012 |
| RV32IMAC | u8×32 | 18.7 | 3144 |
| RV32IMAC | u32×16 | 18.6 | 5896 |
