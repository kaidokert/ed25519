//! Exact conditional-branch calibration for Ed25519/X25519 scalar ladders.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{CalibratedSymbolsConfig, DriverConfig, run_calibrated_symbols};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    // Unset means the workspace profile's own "z". The nested cargo build
    // inherits the same variable, so the calibration and the codegen agree.
    let opt_level =
        std::env::var("CARGO_PROFILE_RELEASE_OPT_LEVEL").unwrap_or_else(|_| "z".to_string());
    let opt_level = opt_level.trim_matches('"');
    let Some(targets) = target::for_opt_level(opt_level) else {
        eprintln!(
            "ladder-branches: no calibration for opt-level {opt_level:?} (have \"s\", \"z\")"
        );
        return ExitCode::from(2);
    };
    run_calibrated_symbols(
        &targets,
        CalibratedSymbolsConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "panic-free-audit",
                fixture_features: &["panic-handler"],
            },
        },
    )
}
