use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use cli_common::{BaseArgs, CheckOutcome, CheckOutputArgs};
use documents::Operation;

#[derive(Parser)]
#[command(version, about = "Generate and verify committed documentation")]
struct Arguments {
    #[command(flatten)]
    base: BaseArgs,
    /// Repository to inspect or update.
    #[arg(long, default_value = ".", global = true)]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Project TOML inputs into deterministic JSON datasets.
    Generate {
        /// Compare without writing files.
        #[arg(long)]
        check: bool,
    },
    /// Compare datasets and rendered documents without writing.
    Check,
    /// Refresh documents, reporting changed files as findings.
    Write,
    /// List templates, datasets and rendered documents.
    Census,
    /// Check one closed public installation evidence document.
    InstallationCheck {
        #[command(subcommand)]
        check: InstallationCheck,
    },
}

#[derive(Subcommand)]
enum InstallationCheck {
    /// Check the supplied tag, key, commit and ancestry facts.
    Tag {
        #[arg(long)]
        facts: PathBuf,
    },
    /// Check the supplied source inventory and build facts.
    Sources {
        #[arg(long)]
        facts: PathBuf,
    },
    /// Check the supplied binary placement facts.
    Placement {
        #[arg(long)]
        facts: PathBuf,
    },
}

/// Justified: This executable bootstrap or termination adapter surrounds installation and handoff to the labelled command boundary; pre-installation control records remain direct and process termination fabricates no completion.
/// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
fn main() -> ExitCode {
    cli_common::select_observation_policy_or_exit("documents");
    documents::install_panic_hook();
    let arguments = cli_common::parse_args_or_exit::<Arguments>();
    let operation = match arguments.command {
        Command::Generate { check } => Operation::Generate { check },
        Command::Check => Operation::Check,
        Command::Write => Operation::Write,
        Command::Census => Operation::Census,
        Command::InstallationCheck { check } => {
            let (selected, facts) = match check {
                InstallationCheck::Tag { facts } => ("tag", facts),
                InstallationCheck::Sources { facts } => ("sources", facts),
                InstallationCheck::Placement { facts } => ("placement", facts),
            };
            return cli_common::run_stdout_json_command("documents", arguments.base.debug, tracing::Level::INFO, || {
                documents::installation::check_file(&arguments.root, selected, &facts)
            });
        }
    };
    cli_common::run_check_command(
        "documents",
        arguments.base.debug,
        tracing::Level::INFO,
        &CheckOutputArgs {
            report: None,
            stamp: None,
        },
        || {
            let report = documents::run(&arguments.root, operation)?;
            Ok::<_, documents::Error>(CheckOutcome {
                clean: report.findings.is_empty(),
                report,
            })
        },
    )
}
