use std::process::ExitCode;

use clap::Parser;
use cli_common::BaseArgs;

#[derive(Parser)]
#[command(version, about = "Exercise the shared JSON panic hook")]
struct Arguments {
    #[command(flatten)]
    base: BaseArgs,
}

/// Exercise the production hook through the same startup function.
///
/// # Panics
/// Always panics after parsing to witness the shared startup hook before any runner.
fn main() -> ExitCode {
    documents::install_panic_hook();
    let _arguments = cli_common::parse_args_or_exit::<Arguments>();
    panic!("contract probe");
}
