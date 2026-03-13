//! # Ignyt CLI
//!
//! The fastest Python code quality engine in the world.
//! Entry point for the `ignyt` binary.

mod commands;
mod explain;
mod output;
mod watch;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The fastest Python code quality engine in the world.
#[derive(Parser, Debug)]
#[command(
    name = "ignyt",
    version,
    about = "The fastest Python code quality engine in the world",
    long_about = "Ignyt is a standalone, self-contained code quality engine written in Rust.\nIt replaces mypy, flake8, bandit, vulture, radon, black, and isort — in one binary."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directories to analyze (defaults to configured `src` paths).
    #[arg(global = true)]
    pub paths: Vec<PathBuf>,

    /// Path to configuration file (default: auto-discover ignyt.toml).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Output format: text (default), json.
    #[arg(long, global = true, default_value = "text")]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run all checks (default when no subcommand given).
    Check {
        /// Files or directories to analyze.
        paths: Vec<PathBuf>,
    },
    /// Format code and sort imports.
    Fmt {
        /// Files or directories to format.
        paths: Vec<PathBuf>,
        /// Only check formatting, don't modify files.
        #[arg(long)]
        check: bool,
    },
    /// Run type checking only.
    Types {
        /// Files or directories to type-check.
        paths: Vec<PathBuf>,
    },
    /// Run security scan and CVE audit.
    Security {
        /// Files or directories to scan.
        paths: Vec<PathBuf>,
    },
    /// Detect dead code and unused symbols.
    Dead {
        /// Files or directories to analyze.
        paths: Vec<PathBuf>,
    },
    /// Analyze cyclomatic and cognitive complexity.
    Complexity {
        /// Files or directories to analyze.
        paths: Vec<PathBuf>,
    },
    /// Auto-fix safe issues.
    Fix {
        /// Files or directories to fix.
        paths: Vec<PathBuf>,
    },
    /// Explain a diagnostic rule in detail.
    Explain {
        /// Rule code to explain (e.g., SEC001, TYPE003).
        code: String,
    },
    /// Watch files for changes and re-run checks.
    Watch {
        /// Files or directories to watch.
        paths: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    // Initialize tracing/logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match commands::run(cli) {
        Ok(has_errors) => {
            if has_errors {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("ignyt: {e}");
            ExitCode::from(2)
        }
    }
}
