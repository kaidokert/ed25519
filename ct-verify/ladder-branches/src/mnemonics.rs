//! Per-ISA conditional-branch mnemonic tables + calibrated
//! branch-count expectations per ladder.
//!
//! The count differs per ISA because loop back-edge lowering does:
//! RISC-V's compare-and-branch instruction naturally emits a
//! conditional back-edge, Thumb-2 uses an unconditional back-edge
//! plus a single entry guard. Fixed-values here; a refactor that
//! legitimately changes the loop shape re-calibrates them.

pub struct IsaSpec {
    pub triple: &'static str,
    /// Conditional-branch mnemonics as `llvm-objdump` renders them.
    /// Unconditional `b`, `bl`, `blx`, `bx`, `j`, `jal`, `c.j` etc.
    /// are excluded — those are the always-taken jumps we don't care
    /// about.
    pub cond_branches: &'static [&'static str],
    /// Optional normalisation applied to each mnemonic before the
    /// set lookup — e.g. Thumb strips `.n`/`.w` size suffixes.
    pub normalize: fn(&str) -> &str,
    pub expected_montgomery_ladder: u32,
    pub expected_scalar_mult_ct: u32,
}

fn thumb_normalize(m: &str) -> &str {
    m.strip_suffix(".n")
        .or_else(|| m.strip_suffix(".w"))
        .unwrap_or(m)
}

fn passthrough(m: &str) -> &str {
    m
}

// Thumb-2: b<cc>[.n|.w], compare-and-branch cbz/cbnz, test-bit-and-
// branch tbz/tbnz. `hs`/`lo` are unsigned aliases for `cs`/`cc` that
// llvm-objdump renders when the compiler emits the unsigned form.
const THUMB_COND_BRANCHES: &[&str] = &[
    "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge",
    "blt", "bgt", "ble", "cbz", "cbnz", "tbz", "tbnz",
];

// RISC-V: real b<cc>, plus llvm-objdump pseudo-mnemonics and the
// compressed compare-with-zero forms.
const RISCV_COND_BRANCHES: &[&str] = &[
    "beq", "bne", "blt", "bge", "bltu", "bgeu", "bgtz", "bltz", "bnez", "beqz", "bgez", "blez",
    "bgt", "ble", "bgtu", "bleu", "c.beqz", "c.bnez",
];

pub const ISAS: &[IsaSpec] = &[
    IsaSpec {
        triple: "thumbv7em-none-eabi",
        cond_branches: THUMB_COND_BRANCHES,
        normalize: thumb_normalize,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct: 1,
    },
    IsaSpec {
        triple: "thumbv7m-none-eabi",
        cond_branches: THUMB_COND_BRANCHES,
        normalize: thumb_normalize,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct: 1,
    },
    IsaSpec {
        triple: "thumbv6m-none-eabi",
        cond_branches: THUMB_COND_BRANCHES,
        normalize: thumb_normalize,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct: 1,
    },
    IsaSpec {
        triple: "riscv32imc-unknown-none-elf",
        cond_branches: RISCV_COND_BRANCHES,
        normalize: passthrough,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct: 2,
    },
    IsaSpec {
        triple: "riscv32imac-unknown-none-elf",
        cond_branches: RISCV_COND_BRANCHES,
        normalize: passthrough,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct: 2,
    },
];

pub fn lookup(triple: &str) -> Option<&'static IsaSpec> {
    ISAS.iter().find(|i| i.triple == triple)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_normalize_strips_size_suffix() {
        assert_eq!(thumb_normalize("beq"), "beq");
        assert_eq!(thumb_normalize("beq.n"), "beq");
        assert_eq!(thumb_normalize("beq.w"), "beq");
    }

    #[test]
    fn riscv_normalize_leaves_compressed_alone() {
        assert_eq!(passthrough("c.beqz"), "c.beqz");
    }

    #[test]
    fn every_isa_has_the_common_mnemonics() {
        for isa in ISAS {
            assert!(isa.cond_branches.contains(&"beq"), "{}", isa.triple);
        }
    }

    #[test]
    fn thumb_includes_unsigned_aliases() {
        assert!(THUMB_COND_BRANCHES.contains(&"bhs"));
        assert!(THUMB_COND_BRANCHES.contains(&"blo"));
    }
}
