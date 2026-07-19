use std::process::ExitCode;

mod fixtures;

fn main() -> ExitCode {
    krabi_caliper::host::ctgrind::run_registered()
}
