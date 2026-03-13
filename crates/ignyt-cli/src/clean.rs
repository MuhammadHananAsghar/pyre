//! # ignyt-clean
//!
//! Removes Python build debris: `__pycache__`, `.pyc`, `.pyo`, `.egg-info`,
//! `dist/`, `build/`, `.pytest_cache`, `.mypy_cache`, and other common
//! artifacts. Similar to `pyclean` but integrated into the Ignyt CLI.

use std::fs;
use std::path::{Path, PathBuf};

use owo_colors::OwoColorize;

/// Directory names that should be removed entirely.
const DEBRIS_DIRS: &[&str] = &[
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pytype",
    ".eggs",
    ".tox",
    ".nox",
    ".hypothesis",
];

/// File extensions that are safe to remove.
const DEBRIS_EXTENSIONS: &[&str] = &["pyc", "pyo"];

/// Directory suffixes that indicate debris.
const DEBRIS_DIR_SUFFIXES: &[&str] = &[".egg-info"];

/// Scan the given paths for Python debris and remove (or list) them.
pub fn clean(paths: &[PathBuf], dry_run: bool) {
    println!(
        "\n{} {} — {}cleaning Python debris\n",
        "🧹".bold(),
        "Ignyt Clean".bold().cyan(),
        if dry_run { "previewing " } else { "" },
    );

    let mut removed_dirs = 0usize;
    let mut removed_files = 0usize;
    let mut freed_bytes = 0u64;

    for path in paths {
        if path.is_dir() {
            walk_and_clean(
                path,
                dry_run,
                &mut removed_dirs,
                &mut removed_files,
                &mut freed_bytes,
            );
        } else {
            eprintln!(
                "  {} {} is not a directory, skipping",
                "⚠".yellow(),
                path.display()
            );
        }
    }

    // Summary.
    let label = if dry_run { "would remove" } else { "removed" };
    println!();
    println!(
        "  {} {} {} director{} and {} file{} ({})",
        "✓".green().bold(),
        label,
        removed_dirs,
        if removed_dirs == 1 { "y" } else { "ies" },
        removed_files,
        if removed_files == 1 { "" } else { "s" },
        human_size(freed_bytes),
    );
    println!();
}

/// Recursively walk a directory and clean debris.
fn walk_and_clean(
    root: &Path,
    dry_run: bool,
    removed_dirs: &mut usize,
    removed_files: &mut usize,
    freed_bytes: &mut u64,
) {
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            // Check if this directory is debris.
            let is_debris_dir = DEBRIS_DIRS.contains(&name.as_ref())
                || DEBRIS_DIR_SUFFIXES.iter().any(|s| name.ends_with(s));

            if is_debris_dir {
                let size = dir_size(&path);
                print_removal(&path, dry_run);
                if !dry_run {
                    if let Err(e) = fs::remove_dir_all(&path) {
                        eprintln!("  {} failed to remove {}: {e}", "✗".red(), path.display());
                        continue;
                    }
                }
                *removed_dirs += 1;
                *freed_bytes += size;
            } else {
                // Recurse into non-debris directories.
                walk_and_clean(&path, dry_run, removed_dirs, removed_files, freed_bytes);
            }
        } else if path.is_file() {
            // Check for .pyc / .pyo files outside __pycache__.
            if let Some(ext) = path.extension() {
                if DEBRIS_EXTENSIONS.contains(&ext.to_string_lossy().as_ref()) {
                    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                    print_removal(&path, dry_run);
                    if !dry_run {
                        if let Err(e) = fs::remove_file(&path) {
                            eprintln!("  {} failed to remove {}: {e}", "✗".red(), path.display());
                            continue;
                        }
                    }
                    *removed_files += 1;
                    *freed_bytes += size;
                }
            }
        }
    }
}

fn print_removal(path: &Path, dry_run: bool) {
    if dry_run {
        println!("  {} {}", "would remove".dimmed(), path.display());
    } else {
        println!("  {} {}", "removed".red(), path.display());
    }
}

/// Compute total size of a directory recursively.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                total += p.metadata().map(|m| m.len()).unwrap_or(0);
            } else if p.is_dir() {
                total += dir_size(&p);
            }
        }
    }
    total
}

/// Format bytes into a human-readable string.
fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
