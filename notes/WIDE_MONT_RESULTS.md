# Wide-REDC Montgomery Integration Results

Date: 2026-02-24

## What Changed

Integrated modmath's wide-REDC Montgomery multiply into the ed25519 verify
hot loop. Feature-gated behind `wide-mont` — only affects `fixed-bigint`
backend (which implements `WideMul` natively).

The ~4000+ `lazy_mod_mul` calls in the JSF scalar multiplication path now
use `wide_montgomery_mul` (REDC-based) instead of `(a * b) % p` (division-based).
Add/sub operations unchanged (they're already cheap).

### Key files

- `new/src/montgomery_ctx.rs` — precomputed Montgomery params (`MontgomeryCtx<T>`)
- `new/src/lazy_mont.rs` — Montgomery-domain multiply wrapper
- `new/src/strict.rs` — feature-gated `_mont` variants of all point operations
- Feature: `wide-mont = ["fixed-bigint", "modmath/wide-mul"]`

## Performance Results

All runs: `--release`, macOS, same machine, `verify_baked` test vector.

| Configuration | Avg Time | Speedup | Status |
|---|---|---|---|
| `fixed-bigint-u64` (baseline) | 12.97 ms | 1.00x | ACCEPT |
| `fixed-bigint-u64,wide-mont` | **9.71 ms** | **1.34x** | ACCEPT |
| `bnum-patched` (unaffected) | 66.6 ms | — | ACCEPT |

## Context

- dalek reference: ~40 us (still ~240x faster than wide-mont path)
- The speedup is modest because the dominant cost is still the sheer number
  of 512-bit multiplications (~4000+), and each REDC still does a full
  512x512-bit `wide_mul`. The win is avoiding the expensive division in
  `% p` — REDC replaces it with multiply+shift.
- Further gains would need: smaller field representation (256-bit with
  careful overflow handling), or limb-level Montgomery (not type-generic).
