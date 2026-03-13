//! Command dispatch and orchestration.
//!
//! Each subcommand collects files, runs the appropriate analysis engine(s),
//! and renders diagnostics to the terminal.

use std::path::PathBuf;
use std::time::Instant;

use ignore::WalkBuilder;
use rayon::prelude::*;

use ignyt_ast::SourceFile;
use ignyt_config::IgnytConfig;
use ignyt_diagnostics::{DiagnosticBag, IgnytError, IgnytResult, Severity};

use crate::output::Renderer;
use crate::{Cli, Command, OutputFormat};

/// Run the CLI command. Returns `true` if there were errors (exit code 1).
pub fn run(cli: Cli) -> IgnytResult<bool> {
    let start = Instant::now();

    // Discover configuration.
    let cwd = std::env::current_dir().map_err(|e| IgnytError::FileRead {
        path: PathBuf::from("."),
        source: e,
    })?;

    let (config, _config_path) = if let Some(ref path) = cli.config {
        (IgnytConfig::load(path)?, Some(path.clone()))
    } else {
        IgnytConfig::discover(&cwd)?
    };

    // Capture the output format before any moves.
    let output_format = cli.format.clone();

    // Determine which command to run.
    let command = cli.command.unwrap_or(Command::Check {
        paths: cli.paths.clone(),
    });

    // Handle non-analysis commands first.
    match &command {
        Command::Explain { code } => {
            crate::explain::explain_rule(code);
            return Ok(false);
        }
        Command::Watch { paths } => {
            let watch_paths = if paths.is_empty() {
                if config.ignyt.src.is_empty() {
                    vec![cwd.clone()]
                } else {
                    config.ignyt.src.iter().map(PathBuf::from).collect()
                }
            } else {
                paths.clone()
            };
            return crate::watch::watch_and_check(&watch_paths, &output_format);
        }
        Command::Clean { paths, dry_run } => {
            let clean_paths = if paths.is_empty() {
                vec![cwd.clone()]
            } else {
                paths.clone()
            };
            crate::clean::clean(&clean_paths, *dry_run);
            return Ok(false);
        }
        Command::Gitignore { path, init } => {
            let project_path = path.clone().unwrap_or_else(|| cwd.clone());
            if *init {
                crate::gitignore::init_gitignore(&project_path);
                return Ok(false);
            }
            let bag = crate::gitignore::validate_gitignore(&project_path);
            let has_errors = bag
                .diagnostics()
                .iter()
                .any(|d| matches!(d.severity, Severity::Error | Severity::Critical));
            return Ok(has_errors);
        }
        _ => {}
    }

    // Collect target paths.
    let target_paths = match &command {
        Command::Check { paths }
        | Command::Fmt { paths, .. }
        | Command::Types { paths }
        | Command::Security { paths }
        | Command::Dead { paths }
        | Command::Complexity { paths }
        | Command::Fix { paths } => {
            if paths.is_empty() {
                // Fall back to configured src paths or current directory.
                if config.ignyt.src.is_empty() {
                    vec![cwd.clone()]
                } else {
                    config.ignyt.src.iter().map(PathBuf::from).collect()
                }
            } else {
                paths.clone()
            }
        }
        // Explain and Watch are handled above and return early.
        Command::Explain { .. }
        | Command::Watch { .. }
        | Command::Clean { .. }
        | Command::Gitignore { .. } => unreachable!(),
    };

    // Collect all Python files.
    let files = collect_python_files(&target_paths);
    let file_count = files.len();

    if file_count == 0 {
        println!("ignyt: no Python files found");
        return Ok(false);
    }

    let renderer = Renderer::new();
    renderer.print_header(file_count);

    // Parse all files in parallel.
    let parsed_files: Vec<_> = files
        .par_iter()
        .filter_map(|path| match SourceFile::parse_file(path) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!("failed to parse {}: {e}", path.display());
                None
            }
        })
        .collect();

    // Run the appropriate checks.
    let mut bag = DiagnosticBag::new();

    match &command {
        Command::Check { .. } => {
            run_all_checks(&parsed_files, &config, &mut bag);
        }
        Command::Types { .. } => {
            run_types(&parsed_files, &mut bag);
        }
        Command::Security { .. } => {
            run_security(&parsed_files, &mut bag);
        }
        Command::Dead { .. } => {
            run_dead(&parsed_files, &mut bag);
        }
        Command::Complexity { .. } => {
            run_complexity(&parsed_files, &config, &mut bag);
        }
        Command::Fmt { check: _, .. } => {
            run_fmt(&parsed_files, &config, &mut bag);
        }
        Command::Fix { .. } => {
            run_fix(&parsed_files, &output_format);
        }
        Command::Explain { .. }
        | Command::Watch { .. }
        | Command::Clean { .. }
        | Command::Gitignore { .. } => unreachable!(),
    }

    let elapsed = start.elapsed();
    let diagnostics = bag.into_sorted();
    let has_errors = diagnostics
        .iter()
        .any(|d| matches!(d.severity, Severity::Error | Severity::Critical));

    match output_format {
        crate::OutputFormat::Json => {
            let json = serde_json::json!({
                "diagnostics": diagnostics,
                "summary": {
                    "total": diagnostics.len(),
                    "errors": diagnostics.iter().filter(|d| d.severity == Severity::Error).count(),
                    "critical": diagnostics.iter().filter(|d| d.severity == Severity::Critical).count(),
                    "warnings": diagnostics.iter().filter(|d| d.severity == Severity::Warning).count(),
                    "hints": diagnostics.iter().filter(|d| d.severity == Severity::Hint).count(),
                    "elapsed_ms": elapsed.as_millis(),
                    "file_count": file_count,
                }
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        crate::OutputFormat::Text => {
            renderer.print_diagnostics(&diagnostics);
            renderer.print_summary(&diagnostics, elapsed);
        }
    }

    Ok(has_errors)
}

/// Run all analysis engines.
fn run_all_checks(files: &[SourceFile], config: &IgnytConfig, bag: &mut DiagnosticBag) {
    run_fmt(files, config, bag);
    run_types(files, bag);
    run_security(files, bag);
    run_dead(files, bag);
    run_complexity(files, config, bag);
}

fn run_types(files: &[SourceFile], bag: &mut DiagnosticBag) {
    let results: Vec<_> = files
        .par_iter()
        .filter_map(|f| ignyt_types::check_types(f).ok())
        .collect();
    for result in results {
        bag.extend(result);
    }
}

fn run_security(files: &[SourceFile], bag: &mut DiagnosticBag) {
    let results: Vec<_> = files
        .par_iter()
        .filter_map(|f| ignyt_security::check_security(f).ok())
        .collect();
    for result in results {
        bag.extend(result);
    }
}

fn run_dead(files: &[SourceFile], bag: &mut DiagnosticBag) {
    let results: Vec<_> = files
        .par_iter()
        .filter_map(|f| ignyt_dead::check_dead_code(f).ok())
        .collect();
    for result in results {
        bag.extend(result);
    }
}

fn run_complexity(files: &[SourceFile], config: &IgnytConfig, bag: &mut DiagnosticBag) {
    let thresholds = ignyt_complexity::ComplexityThresholds {
        max_cyclomatic: config.ignyt.complexity.max_cyclomatic,
        max_cognitive: config.ignyt.complexity.max_cognitive,
        max_lines: config.ignyt.complexity.max_lines,
        max_args: config.ignyt.complexity.max_args,
        ..Default::default()
    };

    let results: Vec<_> = files
        .par_iter()
        .filter_map(|f| ignyt_complexity::check_complexity(f, &thresholds).ok())
        .collect();
    for result in results {
        bag.extend(result);
    }
}

fn run_fmt(files: &[SourceFile], config: &IgnytConfig, bag: &mut DiagnosticBag) {
    let options = ignyt_fmt::FmtOptions {
        line_length: config.ignyt.fmt.line_length,
        check_only: true,
    };

    let results: Vec<_> = files
        .par_iter()
        .filter_map(|f| ignyt_fmt::check_format(f, &options).ok())
        .collect();
    for result in results {
        bag.extend(result);
    }
}

/// Run the auto-fix engine over every file, write back changes, and print a
/// summary of what was fixed.  Errors (file write failures) are logged as
/// warnings so the command still succeeds overall.
fn run_fix(files: &[SourceFile], format: &OutputFormat) {
    // Collect JSON entries for JSON output mode.
    let mut json_entries: Vec<serde_json::Value> = Vec::new();
    let mut total_fixes = 0usize;
    let mut fixed_files = 0usize;

    for file in files {
        let result = match ignyt_fix::apply_fixes(file) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "ignyt fix: failed to compute fixes for {}: {e}",
                    file.path.display()
                );
                continue;
            }
        };

        if result.fixes_applied.is_empty() {
            continue;
        }

        // Write the fixed source back to disk.
        if let Err(e) = std::fs::write(&result.path, &result.source) {
            tracing::warn!("ignyt fix: failed to write {}: {e}", result.path.display());
            continue;
        }

        total_fixes += result.fixes_applied.len();
        fixed_files += 1;

        match format {
            OutputFormat::Text => {
                for fix in &result.fixes_applied {
                    println!(
                        "  fixed  {}:{}  [{}]  {}",
                        result.path.display(),
                        fix.line,
                        fix.code,
                        fix.message
                    );
                }
            }
            OutputFormat::Json => {
                let fix_entries: Vec<serde_json::Value> = result
                    .fixes_applied
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "code": f.code,
                            "message": f.message,
                            "line": f.line,
                        })
                    })
                    .collect();
                json_entries.push(serde_json::json!({
                    "path": result.path.to_string_lossy(),
                    "fixes": fix_entries,
                }));
            }
        }
    }

    match format {
        OutputFormat::Text => {
            println!(
                "\nignyt fix: applied {} fix{} across {} file{}",
                total_fixes,
                if total_fixes == 1 { "" } else { "s" },
                fixed_files,
                if fixed_files == 1 { "" } else { "s" },
            );
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "fixes": json_entries,
                "summary": {
                    "total_fixes": total_fixes,
                    "fixed_files": fixed_files,
                }
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    }
}

/// Walk directories and collect all `.py` files.
fn collect_python_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for path in paths {
        if path.is_file() && path.extension().is_some_and(|ext| ext == "py") {
            files.push(path.clone());
        } else if path.is_dir() {
            let walker = WalkBuilder::new(path)
                .hidden(true) // Skip hidden files
                .git_ignore(true) // Respect .gitignore
                .build();

            for entry in walker.flatten() {
                let p = entry.path();
                if p.is_file() && p.extension().is_some_and(|ext| ext == "py") {
                    files.push(p.to_path_buf());
                }
            }
        }
    }

    files
}
