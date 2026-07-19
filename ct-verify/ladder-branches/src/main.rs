//! Narrow-scope ladder-branch calibration.
//!
//! ed25519_heapless has two secret-scalar consumers on the CT path:
//!
//! - `x25519::montgomery_ladder`
//! - `strict_sign::scalar_mult_ct`
//!
//! Both contain a public-bounded loop-control branch that's invariant
//! in the secret. Per-bit selection uses branchless
//! `conditional_select`. So the right calibration is a **counted
//! per-ISA branch allowance**, not a whole-symbol skip — whole-symbol
//! skip would vacuously pass a regression that added a secret branch.
//!
//! Fails closed if a ladder symbol isn't present in the archive —
//! fat LTO can inline the ladder into its caller, at which point the
//! structural claim isn't observable.
//!
//! This is a supplement to the ctgrind taint gate: ctgrind proves the
//! branches are actually secret-independent under runtime taint;
//! this check proves the structure remains what we calibrated.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use krabi_caliper::host::isa::{ConditionalBranchSpec, conditional_branch_spec};

struct IsaSpec {
    branch_policy: &'static ConditionalBranchSpec,
    expected_montgomery_ladder: u32,
    expected_scalar_mult_ct: u32,
}

fn lookup(triple: &str) -> Option<IsaSpec> {
    let branch_policy = conditional_branch_spec(triple)?;
    let expected_scalar_mult_ct = if triple.starts_with("riscv32") { 2 } else { 1 };
    Some(IsaSpec {
        branch_policy,
        expected_montgomery_ladder: 1,
        expected_scalar_mult_ct,
    })
}

struct Args {
    target: String,
    /// Set by CI when the archive is already built; skip rebuild.
    skip_build: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut target: Option<String> = None;
    let mut skip_build = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--skip-build" => skip_build = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag: {other}"));
            }
            other => {
                if target.is_some() {
                    return Err(format!("unexpected positional argument: {other}"));
                }
                target = Some(other.to_string());
            }
        }
    }
    Ok(Args {
        target: target.unwrap_or_else(|| "thumbv7em-none-eabi".to_string()),
        skip_build,
    })
}

fn print_help() {
    eprintln!(
        "usage: ladder-branches [--skip-build] <target-triple>\n\
         \n\
         Cross-builds panic-free-audit's staticlib for <target-triple>,\n\
         disassembles the two CT scalar-mul ladders, and asserts each\n\
         emits exactly the calibrated number of conditional branches for\n\
         that ISA. Fails closed if a ladder symbol is missing (fat-LTO\n\
         inline) or the count doesn't match calibration."
    );
}

fn workspace_dir() -> PathBuf {
    // The crate lives at ct-verify/ladder-branches/ — its parent is
    // the ct-verify nested workspace.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ladder-branches Cargo.toml has a parent")
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    if let Ok(v) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(v);
    }
    workspace_dir().join("target")
}

fn archive_path(target: &str) -> PathBuf {
    target_dir()
        .join(target)
        .join("release")
        .join("libpanic_free_audit.a")
}

fn find_objdump() -> Result<PathBuf, String> {
    // `RUSTC` is the rustc binary path cargo hands to processes it
    // launches (matters for rustup shims / nested cargo). Fall back
    // to `rustc` on PATH when the env var is absent (e.g. running the
    // binary directly outside `cargo run`).
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot_out = Command::new(&rustc)
        .arg("--print=sysroot")
        .output()
        .map_err(|e| format!("rustc --print=sysroot failed: {e}"))?;
    if !sysroot_out.status.success() {
        return Err("rustc --print=sysroot failed".into());
    }
    let sysroot = String::from_utf8_lossy(&sysroot_out.stdout)
        .trim()
        .to_string();
    let host_out = Command::new(&rustc)
        .arg("-vV")
        .output()
        .map_err(|e| format!("rustc -vV failed: {e}"))?;
    if !host_out.status.success() {
        return Err(format!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&host_out.stderr)
        ));
    }
    let host = String::from_utf8_lossy(&host_out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or_else(|| "rustc -vV missing host: line".to_string())?
        .to_string();
    let path = PathBuf::from(sysroot)
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("llvm-objdump");
    if !path.exists() {
        // Fall back to PATH (system-packaged Rust distros may not
        // ship llvm-tools-preview in the rustup sysroot).
        return Ok(PathBuf::from("llvm-objdump"));
    }
    Ok(path)
}

fn build_archive(target: &str) -> Result<(), String> {
    let ws = workspace_dir();
    // `CARGO` is the cargo binary path cargo hands to processes it
    // launches — using it (rather than `"cargo"` on PATH) keeps the
    // nested build on the same toolchain the outer invocation uses.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg("panic-free-audit")
        .arg("--features")
        .arg("panic-handler")
        .arg("--target")
        .arg(target)
        .current_dir(&ws)
        .status()
        .map_err(|e| format!("cargo build failed to start: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build --target {target} failed"));
    }
    Ok(())
}

fn disassemble(objdump: &Path, archive: &Path) -> Result<String, String> {
    let out = Command::new(objdump)
        .arg("-d")
        .arg("--demangle")
        .arg(archive)
        .output()
        .map_err(|e| format!("llvm-objdump failed to start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "llvm-objdump failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Iterate `(section_header_line, iter_body_lines)` over the
/// disassembly. `section_header_line` is the full `Disassembly of
/// section <name>:` line; the body iter yields every line up to (but
/// excluding) the next `Disassembly of section` header.
fn sections(disasm: &str) -> impl Iterator<Item = (&str, Vec<&str>)> {
    let mut lines = disasm.lines().peekable();
    std::iter::from_fn(move || {
        let header = loop {
            let l = lines.next()?;
            if l.starts_with("Disassembly of section") {
                break l;
            }
        };
        let mut body = Vec::new();
        while let Some(&next) = lines.peek() {
            if next.starts_with("Disassembly of section") {
                break;
            }
            body.push(lines.next().unwrap());
        }
        Some((header, body))
    })
}

fn find_ladder<'a>(disasm: &'a str, ladder_name: &str) -> Option<(&'a str, Vec<&'a str>)> {
    sections(disasm).find(|(header, _)| header.contains(ladder_name))
}

fn count_conditional_branches(body: &[&str], isa: &IsaSpec) -> u32 {
    let mut count = 0;
    for line in body {
        // Instruction lines look like:
        //   `    1a: f000 812f     beq.w   0x27c <...>`
        // The mnemonic is the first non-empty token after the tab.
        let tail = match line.split_once('\t') {
            Some((_, tail)) => tail,
            None => continue,
        };
        let mnemonic = match tail.split_whitespace().next() {
            Some(m) => m,
            None => continue,
        };
        let normalized = (isa.branch_policy.normalize)(mnemonic);
        if isa.branch_policy.mnemonics.contains(&normalized) {
            count += 1;
        }
    }
    count
}

struct LadderCheck {
    display_name: &'static str,
    match_substring: &'static str,
    expected: u32,
}

fn ladder_checks_for(isa: &IsaSpec) -> [LadderCheck; 2] {
    [
        LadderCheck {
            display_name: "x25519::montgomery_ladder",
            match_substring: "montgomery_ladder",
            expected: isa.expected_montgomery_ladder,
        },
        LadderCheck {
            display_name: "strict_sign::scalar_mult_ct",
            match_substring: "scalar_mult_ct",
            expected: isa.expected_scalar_mult_ct,
        },
    ]
}

enum Verdict {
    Ok(u32),
    NotFound,
    Mismatch {
        found: u32,
        expected: u32,
        /// Full section (header + all body lines) so a reviewer can
        /// see the surrounding control flow, not just the branch
        /// mnemonics we picked out. Wrong-section selection is easy
        /// to miss from just branch lines.
        section: Vec<String>,
    },
}

fn check_ladder(disasm: &str, check: &LadderCheck, isa: &IsaSpec) -> Verdict {
    let Some((header, body)) = find_ladder(disasm, check.match_substring) else {
        return Verdict::NotFound;
    };
    let found = count_conditional_branches(&body, isa);
    if found == check.expected {
        return Verdict::Ok(found);
    }
    let mut section: Vec<String> = Vec::with_capacity(body.len() + 1);
    section.push(header.to_string());
    section.extend(body.iter().map(|s| s.to_string()));
    Verdict::Mismatch {
        found,
        expected: check.expected,
        section,
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            print_help();
            return ExitCode::from(2);
        }
    };
    let isa = match lookup(&args.target) {
        Some(i) => i,
        None => {
            eprintln!(
                "error: unknown target {}. Add shared ISA policy and local ladder calibration.",
                args.target
            );
            return ExitCode::from(2);
        }
    };
    let objdump = match find_objdump() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if !args.skip_build {
        if let Err(e) = build_archive(&args.target) {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    }
    let archive = archive_path(&args.target);
    if !archive.exists() {
        eprintln!("error: expected archive not found at {}", archive.display());
        return ExitCode::FAILURE;
    }
    let disasm = match disassemble(&objdump, &archive) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("[ladder-branches] {}", args.target);
    let mut any_failed = false;
    for check in ladder_checks_for(&isa) {
        match check_ladder(&disasm, &check, &isa) {
            Verdict::Ok(n) => {
                println!(
                    "  OK: {} — {} conditional branch(es) matches calibration",
                    check.display_name, n
                );
            }
            Verdict::NotFound => {
                eprintln!(
                    "  FAIL: {} — section not found in archive (LTO inlined into caller?)",
                    check.display_name
                );
                any_failed = true;
            }
            Verdict::Mismatch {
                found,
                expected,
                section,
            } => {
                eprintln!(
                    "  FAIL: {} — expected {expected} conditional branch(es), found {found}",
                    check.display_name
                );
                for line in section {
                    eprintln!("    {line}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DISASM: &str = "\
Disassembly of section .text._ZN16ed25519_heapless6x2551917montgomery_ladder17habcdef0123456789E:

00000000 <ed25519_heapless::x25519::montgomery_ladder>:
       0: b580         	push	{r7, lr}
       2: 466f         	mov	r7, sp
       4: 4770         	bx	lr
      1a: f000 812f    	beq.w	0x27c <ed25519_heapless::x25519::montgomery_ladder+0x25e>
      1e: 47d0         	blx	r10

Disassembly of section .text._ZN16ed25519_heapless11strict_sign14scalar_mult_ct17h9876543210fedcbaE:

00000000 <ed25519_heapless::strict_sign::scalar_mult_ct>:
       0: b580         	push	{r7, lr}
      da: d036         	beq	0x14a <ed25519_heapless::strict_sign::scalar_mult_ct+0x6c>
      de: e7be         	b	0x5e

Disassembly of section .text.something_else:
       0: e7fe         	b	0x0
";

    fn thumb_isa() -> IsaSpec {
        lookup("thumbv7em-none-eabi").unwrap()
    }

    #[test]
    fn parse_sections_splits_correctly() {
        let count = sections(SAMPLE_DISASM).count();
        assert_eq!(count, 3);
    }

    #[test]
    fn find_ladder_by_substring() {
        let (h, _) = find_ladder(SAMPLE_DISASM, "montgomery_ladder").unwrap();
        assert!(h.contains("montgomery_ladder"));
    }

    #[test]
    fn count_conditional_ignores_unconditional() {
        let isa = thumb_isa();
        let (_, body) = find_ladder(SAMPLE_DISASM, "scalar_mult_ct").unwrap();
        // Two branches in the section: `beq` (conditional) and `b`
        // (unconditional). Only `beq` should count.
        assert_eq!(count_conditional_branches(&body, &isa), 1);
    }

    #[test]
    fn count_conditional_counts_wide_thumb() {
        let isa = thumb_isa();
        let (_, body) = find_ladder(SAMPLE_DISASM, "montgomery_ladder").unwrap();
        // `beq.w` normalizes to `beq` → 1.
        assert_eq!(count_conditional_branches(&body, &isa), 1);
    }

    #[test]
    fn missing_ladder_returns_not_found() {
        let isa = thumb_isa();
        let check = LadderCheck {
            display_name: "nonexistent",
            match_substring: "nonexistent_ladder_xyz",
            expected: 1,
        };
        match check_ladder(SAMPLE_DISASM, &check, &isa) {
            Verdict::NotFound => {}
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn mismatch_reports_full_section() {
        let isa = thumb_isa();
        let check = LadderCheck {
            display_name: "scalar_mult_ct",
            match_substring: "scalar_mult_ct",
            expected: 99,
        };
        match check_ladder(SAMPLE_DISASM, &check, &isa) {
            Verdict::Mismatch { found, section, .. } => {
                assert_eq!(found, 1);
                assert!(section[0].contains("scalar_mult_ct"));
                assert!(section.iter().any(|l| l.contains("beq")));
                assert!(section.iter().any(|l| l.contains("push")));
            }
            _ => panic!("expected Mismatch"),
        }
    }
}
