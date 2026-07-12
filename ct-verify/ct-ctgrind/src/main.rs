//! Valgrind-based taint verifier for ed25519_heapless's secret path.
//!
//! Each fixture from `fixtures.rs` calls one entry point of
//! `panic-free-audit`'s C ABI with its secret input marked
//! `MAKE_MEM_UNDEFINED` via crabgrind. Valgrind memcheck then flags
//! any conditional jump or memory access that depends on those
//! tainted bytes — including inside inlined upstream primitives —
//! which surfaces every leak reachable from a whole-operation sign or
//! key-exchange call, not just those we would have thought to write a
//! primitive fixture for.
//!
//! Run as:
//!   valgrind --tool=memcheck --error-limit=no --error-exitcode=0 ct-ctgrind
//!
//! `--error-exitcode=0` matters: Valgrind must NOT set the process
//! exit code, because this driver decides pass/fail based on which
//! fixtures (positive vs. negative) tripped. `--error-limit=no` is
//! equally load-bearing — memcheck stops collecting after 1,000
//! distinct error contexts (or 10M total), and a saturated counter
//! would make every later fixture read as clean.

use std::process::ExitCode;

mod fixtures;
mod macros;
mod valgrind;

pub struct Fixture {
    pub name: &'static str,
    pub run: fn(),
}

inventory::collect!(Fixture);

fn is_positive(name: &str) -> bool {
    name.starts_with("ct_fix__")
}

fn is_negative(name: &str) -> bool {
    name.starts_with("nct_fix__neg__")
}

fn main() -> ExitCode {
    if !valgrind::is_under_valgrind() {
        eprintln!(
            "error: ct-ctgrind must be run under valgrind \
             (e.g. `valgrind --tool=memcheck --error-limit=no --error-exitcode=0 ct-ctgrind`)"
        );
        return ExitCode::from(2);
    }

    let mut pos_pass: usize = 0;
    let mut pos_fail: Vec<&'static str> = Vec::new();
    let mut neg_seen: usize = 0;
    let mut neg_no_trip: Vec<&'static str> = Vec::new();
    let mut unclassified: Vec<&'static str> = Vec::new();

    let mut fixtures: Vec<&Fixture> = inventory::iter::<Fixture>().collect();
    fixtures.sort_by_key(|f| f.name);

    for fixture in fixtures {
        let before = valgrind::count_errors();
        (fixture.run)();
        let after = valgrind::count_errors();
        let tripped = after > before;

        if is_positive(fixture.name) {
            if tripped {
                pos_fail.push(fixture.name);
            } else {
                pos_pass += 1;
            }
        } else if is_negative(fixture.name) {
            neg_seen += 1;
            if !tripped {
                neg_no_trip.push(fixture.name);
            }
        } else {
            // Fail closed — a fixture whose name matches neither
            // prefix is almost certainly a rename/typo that would
            // otherwise vanish from coverage silently.
            unclassified.push(fixture.name);
        }
    }

    println!("==== ct-ctgrind report ====");
    println!(
        "  ct_fix__*       passed: {}  failed: {}",
        pos_pass,
        pos_fail.len()
    );
    println!(
        "  nct_fix__neg__* tripped: {}/{}",
        neg_seen - neg_no_trip.len(),
        neg_seen
    );
    for f in &pos_fail {
        println!("    FAIL (positive tripped Valgrind): {}", f);
    }
    for f in &neg_no_trip {
        println!("    FAIL (negative didn't trip): {}", f);
    }
    for f in &unclassified {
        println!("    FAIL (unclassified fixture name): {}", f);
    }

    if pos_pass + pos_fail.len() == 0 {
        eprintln!("error: no positive fixtures registered — registry empty?");
        return ExitCode::FAILURE;
    }
    if neg_seen == 0 {
        eprintln!("error: no negative controls registered — registry empty?");
        return ExitCode::FAILURE;
    }
    if !pos_fail.is_empty() || !neg_no_trip.is_empty() || !unclassified.is_empty() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
