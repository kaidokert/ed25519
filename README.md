### ed25519 heapless fork

[![crate](https://img.shields.io/crates/v/ed25519_heapless.svg)](https://crates.io/crates/ed25519_heapless)
[![documentation](https://docs.rs/ed25519_heapless/badge.svg)](https://docs.rs/ed25519_heapless/)
[![Rust](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/rust.yml)
[![AVR](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/avr.yml)
[![Cortex-M](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/cortex_m.yml)
[![RISC-V](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml/badge.svg)](https://github.com/kaidokert/ed25519/actions/workflows/riscv.yml)

This is a fork of the `ed25519` crate, ported to microcontrollers. It is generic over the bignum backend: bring your own by implementing `UnsignedModularInt`, or use [fixed-bigint](https://crates.io/crates/fixed-bigint) (the reference backend, fixed-width or runtime-length). Tested on 8-bit AVR, Cortex-M and RISC-V.

The implementation balances code size, stack usage and execution speed rather than optimizing purely for speed. Alongside signature verification (e.g., bootloaders), it provides Ed25519 signing, X25519 key exchange (with optional blinding), and a blinded X25519 KEM (`kem::Kem`). These touch secret material, but the field arithmetic is not yet audited as constant-time — see the crate's *Constant-time scope* docs. Callers own the RNG and secure key storage.

#### Resource usage (v0.5.2)

**Ed25519 signature verification**

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| AVR ATmega2560 | u8×32 | 17.7 | 2857 |
| Cortex-M0 | u8×32 | 12.4 | 2908 |
| Cortex-M3 | u8×32 | 11.8 | 2828 |
| Cortex-M0 | u32×16 | 12.6 | 5724 |
| Cortex-M3 | u32×16 | 11.9 | 5612 |
| RV32IMAC | u8×32 | 15.4 | 2640 |
| RV32IMAC | u32×16 | 15.1 | 5500 |

**X25519 key exchange** (Cortex-M)

| Target | Backend | .text (KiB) | Stack (bytes) |
| ------ | ------- | ----------: | ------------: |
| Cortex-M0 | u8×32 | 5.2 | 1636 |
| Cortex-M3 | u8×32 | 5.1 | 1556 |
| Cortex-M0 | u32×16 | 5.6 | 3284 |
| Cortex-M3 | u32×16 | 5.2 | 3196 |

Figures are the incremental cost of the operation itself, measured as operation-minus-baseline in the demo harnesses (from the merge-commit CI run) — the flash and stack attributable to the crypto, not the whole binary's footprint.
