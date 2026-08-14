### ed25519 heapless fork

[![crate](https://img.shields.io/crates/v/ed25519_heapless.svg)](https://crates.io/crates/ed25519_heapless)
[![documentation](https://docs.rs/ed25519_heapless/badge.svg)](https://docs.rs/ed25519_heapless/)
[![Rust](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml)
[![AVR](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml)

This is a fork of the `ed25519` crate, ported to microcontrollers. It is generic over the bignum backend: bring your own by implementing `UnsignedModularInt`, or use [fixed-bigint](https://crates.io/crates/fixed-bigint) (the reference backend, fixed-width or runtime-length). Tested on 8-bit AVR, Cortex-M and RISC-V.

The implementation balances code size, stack usage and execution speed rather than optimizing purely for speed. Alongside signature verification (e.g., bootloaders), it provides Ed25519 signing, X25519 key exchange (with optional blinding), and a blinded X25519 KEM (`kem::Kem`). These touch secret material, but the field arithmetic is not yet audited as constant-time — see the crate's *Constant-time scope* docs. Callers own the RNG and secure key storage.

#### Resource usage (v0.5.1)

**Ed25519 signature verification**

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| AVR ATmega2560 | u8×32 | 16.9 | 2856 |
| Cortex-M0 | u8×32 | 10.9 | 2892 |
| Cortex-M3 | u8×32 | 10.4 | 2820 |
| Cortex-M0 | u32×16 | 11.1 | 5724 |
| Cortex-M3 | u32×16 | 10.5 | 5612 |
| RV32IMAC | u8×32 | 14.2 | 2656 |
| RV32IMAC | u32×16 | 13.9 | 5516 |

**X25519 key exchange** (Cortex-M)

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| Cortex-M0 | u8×32 | 5.0 | 1636 |
| Cortex-M3 | u8×32 | 4.9 | 1556 |
| Cortex-M0 | u32×16 | 5.4 | 3324 |
| Cortex-M3 | u32×16 | 5.1 | 3260 |

Figures are the incremental cost of the operation itself, measured as operation-minus-baseline in the demo harnesses (from the merge-commit CI run) — the flash and stack attributable to the crypto, not the whole binary's footprint.
