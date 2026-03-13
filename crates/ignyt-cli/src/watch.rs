//! File-watching mode for `ignyt watch`.
//!
//! Uses `notify` to watch directories for `.py` file changes, then re-runs
//! all checks on each change (debounced).

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use owo_colors::OwoColorize;
use rayon::prelude::*;

use ignyt_ast::SourceFile;
use ignyt_config::IgnytConfig;
use ignyt_diagnostics::{DiagnosticBag, IgnytResult};

use crate::output::Renderer;
use crate::OutputFormat;

/// Watch the given paths for `.py` file changes and re-run checks on each
/// change. This function blocks indefinitely (until Ctrl-C).
pub fn watch_and_check(paths: &[PathBuf], format: &OutputFormat) -> IgnytResult<bool> {
    println!(
        "\n{} {} — watching for changes (Ctrl-C to stop)\n",
        "👁".bold(),
        "Ignyt Watch".bold().cyan(),
    );

    // Run initial check.
    run_check_cycle(paths, format);

    // Set up file watcher.
    let (tx, rx) = mpsc::channel();
    let mut debouncer = new_debouncer(std::time::Duration::from_millis(500), tx).map_err(|e| {
        ignyt_diagnostics::IgnytError::ConfigError {
            message: format!("failed to create file watcher: {e}"),
        }
    })?;

    for path in paths {
        debouncer
            .watcher()
            .watch(path, notify::RecursiveMode::Recursive)
            .map_err(|e| ignyt_diagnostics::IgnytError::ConfigError {
                message: format!("failed to watch {}: {e}", path.display()),
            })?;
    }

    println!(
        "  {} Watching {} path{} for changes...\n",
        "⏳".dimmed(),
        paths.len(),
        if paths.len() == 1 { "" } else { "s" },
    );

    // Event loop.
    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                // Only re-run if a .py file changed.
                let has_py_change = events.iter().any(|e| {
                    e.kind == DebouncedEventKind::Any
                        && e.path.extension().is_some_and(|ext| ext == "py")
                });

                if has_py_change {
                    // Clear screen for a fresh view.
                    print!("\x1B[2J\x1B[1;1H");
                    println!(
                        "\n{} {} — change detected, re-checking...\n",
                        "⚡".bold(),
                        "Ignyt Watch".bold().cyan(),
                    );
                    run_check_cycle(paths, format);
                    println!("  {} Watching for changes...\n", "⏳".dimmed(),);
                }
            }
            Ok(Err(errors)) => {
                tracing::warn!("watch error: {errors}");
            }
            Err(_) => {
                // Channel closed — exit.
                break;
            }
        }
    }

    Ok(false)
}

/// Run a single check cycle: collect files, parse, analyze, print results.
fn run_check_cycle(paths: &[PathBuf], format: &OutputFormat) {
    let start = Instant::now();
    let files = collect_python_files(paths);
    let file_count = files.len();

    if file_count == 0 {
        println!("  ignyt: no Python files found");
        return;
    }

    let renderer = Renderer::new();
    renderer.print_header(file_count);

    let parsed_files: Vec<_> = files
        .par_iter()
        .filter_map(|path| SourceFile::parse_file(path).ok())
        .collect();

    let cwd = std::env::current_dir().unwrap_or_default();
    let config = IgnytConfig::discover(&cwd)
        .map(|(c, _)| c)
        .unwrap_or_default();

    let mut bag = DiagnosticBag::new();

    // Run all checks.
    let results: Vec<_> = parsed_files
        .par_iter()
        .filter_map(|f| ignyt_types::check_types(f).ok())
        .collect();
    for r in results {
        bag.extend(r);
    }

    let results: Vec<_> = parsed_files
        .par_iter()
        .filter_map(|f| ignyt_security::check_security(f).ok())
        .collect();
    for r in results {
        bag.extend(r);
    }

    let results: Vec<_> = parsed_files
        .par_iter()
        .filter_map(|f| ignyt_dead::check_dead_code(f).ok())
        .collect();
    for r in results {
        bag.extend(r);
    }

    let thresholds = ignyt_complexity::ComplexityThresholds {
        max_cyclomatic: config.ignyt.complexity.max_cyclomatic,
        max_cognitive: config.ignyt.complexity.max_cognitive,
        max_lines: config.ignyt.complexity.max_lines,
        max_args: config.ignyt.complexity.max_args,
        ..Default::default()
    };
    let results: Vec<_> = parsed_files
        .par_iter()
        .filter_map(|f| ignyt_complexity::check_complexity(f, &thresholds).ok())
        .collect();
    for r in results {
        bag.extend(r);
    }

    let fmt_options = ignyt_fmt::FmtOptions {
        line_length: config.ignyt.fmt.line_length,
        check_only: true,
    };
    let results: Vec<_> = parsed_files
        .par_iter()
        .filter_map(|f| ignyt_fmt::check_format(f, &fmt_options).ok())
        .collect();
    for r in results {
        bag.extend(r);
    }

    let elapsed = start.elapsed();
    let diagnostics = bag.into_sorted();

    match format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "diagnostics": diagnostics,
                "summary": {
                    "total": diagnostics.len(),
                    "elapsed_ms": elapsed.as_millis(),
                    "file_count": file_count,
                }
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        OutputFormat::Text => {
            renderer.print_diagnostics(&diagnostics);
            renderer.print_summary(&diagnostics, elapsed);
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
            let mut builder = ignore::WalkBuilder::new(path);
            ignore::WalkBuilder::hidden(&mut builder, true);
            builder.git_ignore(true);
            let walker = builder.build();

            for entry in walker {
                let Ok(entry) = entry else { continue };
                let p = entry.path();
                if p.is_file() && p.extension().is_some_and(|ext| ext == "py") {
                    files.push(p.to_path_buf());
                }
            }
        }
    }
    files
}
