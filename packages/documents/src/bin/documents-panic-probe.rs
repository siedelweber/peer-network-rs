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
/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
fn main() -> ExitCode {
    documents::install_panic_hook();
    let _arguments = cli_common::parse_args_or_exit::<Arguments>();
    panic!("contract probe");
}
