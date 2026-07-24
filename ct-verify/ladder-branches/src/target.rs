//! Client-owned symbol selectors and per-target branch calibrations.
//!
//! Both scalar consumers contain public-bounded loop-control branches; their
//! per-bit selection remains branchless. Exact counts are intentional: a
//! whole-symbol exemption would hide a newly introduced secret branch. The
//! shared driver also requires exactly one match for each selector, failing
//! closed if fat LTO or symbol drift makes the structural claim unobservable.

use krabi_caliper::host::ct_asm::{CalibratedSymbolsTarget as TargetSpec, SymbolCalibration};
use krabi_caliper::host::isa as mnemonics;

const THUMB_CALIBRATIONS: &[SymbolCalibration] = &[
    SymbolCalibration {
        display_name: "x25519::montgomery_ladder",
        selector: "montgomery_ladder",
        expected_branches: 1,
    },
    SymbolCalibration {
        display_name: "strict_sign::scalar_mult_ct",
        selector: "scalar_mult_ct",
        expected_branches: 1,
    },
];

const RISCV_CALIBRATIONS: &[SymbolCalibration] = &[
    SymbolCalibration {
        display_name: "x25519::montgomery_ladder",
        selector: "montgomery_ladder",
        // The shared instruction parser recognizes both RISC-V loop-control
        // branches; the previous tab-based parser missed one of them.
        expected_branches: 2,
    },
    SymbolCalibration {
        display_name: "strict_sign::scalar_mult_ct",
        selector: "scalar_mult_ct",
        expected_branches: 2,
    },
];

const AARCH64_CALIBRATIONS: &[SymbolCalibration] = &[
    SymbolCalibration {
        display_name: "x25519::montgomery_ladder",
        selector: "montgomery_ladder",
        expected_branches: 1,
    },
    SymbolCalibration {
        display_name: "strict_sign::scalar_mult_ct",
        selector: "scalar_mult_ct",
        expected_branches: 1,
    },
];

const X86_64_CALIBRATIONS: &[SymbolCalibration] = &[
    SymbolCalibration {
        display_name: "x25519::montgomery_ladder",
        selector: "montgomery_ladder",
        expected_branches: 1,
    },
    SymbolCalibration {
        display_name: "strict_sign::scalar_mult_ct",
        selector: "scalar_mult_ct",
        expected_branches: 1,
    },
];

/// Every target supported by the previous standalone driver, plus the two 64-bit
/// host ISAs. CI exercises one representative lowering per ISA family; the
/// sibling triples remain available for local calibration checks.
pub const TARGETS: &[TargetSpec] = &[
    TargetSpec {
        triple: "thumbv7em-none-eabi",
        priority: 1,
        toolchain: "1.86.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        calibrations: THUMB_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv7m-none-eabi",
        priority: 1,
        toolchain: "1.86.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        calibrations: THUMB_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "thumbv6m-none-eabi",
        priority: 2,
        toolchain: "1.86.0",
        forbidden: mnemonics::THUMB_FORBIDDEN,
        allowed_cmov: mnemonics::THUMB_ALLOWED,
        calibrations: THUMB_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "riscv32imc-unknown-none-elf",
        priority: 3,
        toolchain: "1.86.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        calibrations: RISCV_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "riscv32imac-unknown-none-elf",
        priority: 3,
        toolchain: "1.86.0",
        forbidden: mnemonics::RISCV_FORBIDDEN,
        allowed_cmov: &[],
        calibrations: RISCV_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "aarch64-unknown-none",
        priority: 4,
        toolchain: "1.86.0",
        forbidden: mnemonics::AARCH64_FORBIDDEN,
        allowed_cmov: mnemonics::AARCH64_ALLOWED,
        calibrations: AARCH64_CALIBRATIONS,
        extra_cargo_args: &[],
    },
    TargetSpec {
        triple: "x86_64-unknown-none",
        priority: 4,
        toolchain: "1.86.0",
        forbidden: mnemonics::X86_64_FORBIDDEN,
        allowed_cmov: mnemonics::X86_64_ALLOWED,
        calibrations: X86_64_CALIBRATIONS,
        extra_cargo_args: &[],
    },
];
