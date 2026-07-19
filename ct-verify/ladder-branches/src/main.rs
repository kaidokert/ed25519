//! Exact conditional-branch calibration for Ed25519/X25519 scalar ladders.

mod target;

use std::path::Path;
use std::process::ExitCode;

use krabi_caliper::host::ct_asm::{CalibratedSymbolsConfig, DriverConfig, run_calibrated_symbols};

fn main() -> ExitCode {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ct-verify workspace");
    run_calibrated_symbols(
        target::TARGETS,
        CalibratedSymbolsConfig {
            driver: DriverConfig {
                workspace,
                fixture_package: "panic-free-audit",
                fixture_features: &["panic-handler"],
            },
        },
    )
}
