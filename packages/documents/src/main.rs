use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use cli_common::{BaseArgs, CheckOutputArgs};
use documents::Operation;

#[derive(Parser)]
#[command(version, about = "Generate and verify committed documentation")]
struct Arguments {
    #[command(flatten)]
    base: BaseArgs,
    /// Repository to inspect or update.
    #[arg(long, default_value = ".", global = true)]
    root: PathBuf,
    /// Return the whole operation report on standard output.
    #[arg(long, value_enum, global = true)]
    output: Option<Output>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Project TOML inputs into deterministic JSON datasets.
    Generate {
        #[arg(value_enum)]
        mode: Mode,
        #[command(flatten)]
        files: CheckOutputArgs,
    },
    /// Compare or refresh rendered documents.
    Render {
        #[arg(value_enum)]
        mode: Mode,
        #[command(flatten)]
        files: CheckOutputArgs,
    },
    /// List templates, datasets and rendered documents.
    Census,
    /// Check one closed public installation evidence document.
    InstallationCheck {
        #[command(subcommand)]
        check: InstallationCheck,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Check,
    Write,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Report,
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
    let (operation, check, files) = match arguments.command {
        Command::Generate { mode, files } => (
            Operation::Generate {
                check: matches!(mode, Mode::Check),
            },
            matches!(mode, Mode::Check),
            files,
        ),
        Command::Render { mode, files } => (
            Operation::Render {
                check: matches!(mode, Mode::Check),
            },
            matches!(mode, Mode::Check),
            files,
        ),
        Command::Census => {
            return cli_common::run_stdout_json_command("documents", arguments.base.debug, tracing::Level::INFO, || {
                documents::run(&arguments.root, Operation::Census)
            });
        }
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
    cli_common::run_document_mode(
        "documents",
        arguments.base.debug,
        tracing::Level::INFO,
        check,
        arguments.output.is_some(),
        &files,
        || {
            let report = documents::run(&arguments.root, operation)?;
            let count = report.findings.len();
            Ok::<_, documents::Error>((report, count))
        },
    )
}
