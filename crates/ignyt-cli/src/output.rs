//! Terminal output rendering for Ignyt diagnostics.

use std::time::Duration;

use ignyt_diagnostics::{Diagnostic, Severity};
use owo_colors::OwoColorize;

/// Renders diagnostics and summaries to the terminal.
pub struct Renderer;

impl Renderer {
    pub fn new() -> Self {
        Self
    }

    /// Print the analysis header.
    pub fn print_header(&self, file_count: usize) {
        println!(
            "\n{} {} — analyzing {} file{}",
            "⚡".bold(),
            "Ignyt".bold().cyan(),
            file_count.bold(),
            if file_count == 1 { "" } else { "s" },
        );
        println!();
    }

    /// Print all diagnostics grouped by severity.
    pub fn print_diagnostics(&self, diagnostics: &[Diagnostic]) {
        if diagnostics.is_empty() {
            return;
        }

        println!("{}", "─".repeat(60).dimmed());
        println!();

        for diag in diagnostics {
            let code_colored = match diag.severity {
                Severity::Critical | Severity::Error => diag.code.bold().red().to_string(),
                Severity::Warning => diag.code.bold().yellow().to_string(),
                Severity::Hint => diag.code.bold().blue().to_string(),
            };

            println!(
                "  {:<8} {:<30} {}",
                code_colored,
                diag.location.to_string().dimmed(),
                diag.message,
            );

            if let Some(ref suggestion) = diag.suggestion {
                println!("           {} {suggestion}", "→".dimmed());
            }
        }

        println!();
    }

    /// Print the summary footer.
    pub fn print_summary(&self, diagnostics: &[Diagnostic], elapsed: Duration) {
        println!("{}", "─".repeat(60).dimmed());

        let errors = diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count();
        let critical = diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Critical)
            .count();
        let warnings = diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count();
        let hints = diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Hint)
            .count();

        let mut parts = Vec::new();

        if critical > 0 {
            parts.push(format!("{} critical", critical).red().to_string());
        }
        if errors > 0 {
            parts.push(
                format!("{} error{}", errors, if errors == 1 { "" } else { "s" })
                    .red()
                    .to_string(),
            );
        }
        if warnings > 0 {
            parts.push(
                format!(
                    "{} warning{}",
                    warnings,
                    if warnings == 1 { "" } else { "s" }
                )
                .yellow()
                .to_string(),
            );
        }
        if hints > 0 {
            parts.push(
                format!("{} hint{}", hints, if hints == 1 { "" } else { "s" })
                    .blue()
                    .to_string(),
            );
        }

        if parts.is_empty() {
            println!(
                "  {} completed in {:.1}s",
                "All checks passed ✓".green().bold(),
                elapsed.as_secs_f64()
            );
        } else {
            println!(
                "  {} · completed in {:.1}s",
                parts.join(" · "),
                elapsed.as_secs_f64()
            );
        }

        if diagnostics.iter().any(|d| d.fixable) {
            println!(
                "\n  Run {} to auto-fix safe issues",
                "ignyt fix".bold().cyan()
            );
        }

        println!();
    }
}
