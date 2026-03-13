//! # ignyt-gitignore
//!
//! Validates `.gitignore` files for Python projects. Checks for missing
//! essential patterns, duplicate entries, invalid syntax, overly broad
//! rules, and missing secrets/env patterns.

use std::collections::HashSet;
use std::path::Path;

use owo_colors::OwoColorize;

use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, Location, Severity};

/// Essential Python patterns that every Python project should ignore.
const ESSENTIAL_PYTHON_PATTERNS: &[(&str, &str)] = &[
    ("__pycache__/", "compiled bytecode cache"),
    ("*.pyc", "compiled bytecode files"),
    (".env", "environment variables with secrets"),
    ("*.egg-info/", "package metadata directory"),
    ("dist/", "built distribution packages"),
    ("build/", "build output directory"),
    ("venv/", "virtual environment"),
];

/// Patterns that are too broad and may accidentally ignore important files.
const OVERLY_BROAD_PATTERNS: &[(&str, &str)] = &[
    ("*.py", "ignores all Python source files"),
    ("*.rs", "ignores all Rust source files"),
    ("*.js", "ignores all JavaScript source files"),
    ("*.ts", "ignores all TypeScript source files"),
    ("src/", "ignores entire source directory"),
    ("src", "ignores entire source directory"),
    ("lib/", "ignores entire lib directory"),
    ("app/", "ignores entire app directory"),
    ("*.toml", "ignores all TOML config files"),
    ("*.yaml", "ignores all YAML files"),
    ("*.yml", "ignores all YAML files"),
    ("*.json", "ignores all JSON files"),
    ("*.md", "ignores all Markdown files"),
    ("*.txt", "ignores all text files"),
    ("Cargo.toml", "ignores Rust workspace config"),
    ("pyproject.toml", "ignores Python project config"),
    ("README.md", "ignores project README"),
    ("LICENSE", "ignores project license"),
];

/// Secrets-related patterns that should typically be ignored.
const SECRETS_PATTERNS: &[(&str, &str)] = &[
    (".env", "environment variables file"),
    (".env.local", "local environment overrides"),
    ("*.pem", "private key files"),
    ("*.key", "private key files"),
];

/// Validate a `.gitignore` file at the given project root.
pub fn validate_gitignore(project_path: &Path) -> DiagnosticBag {
    let mut bag = DiagnosticBag::new();
    let gitignore_path = project_path.join(".gitignore");

    println!(
        "\n{} {} — validating .gitignore\n",
        "🔍".bold(),
        "Ignyt Gitignore".bold().cyan(),
    );

    // GIT001: Check if .gitignore exists at all.
    if !gitignore_path.exists() {
        bag.push(
            Diagnostic::new(
                "GIT001",
                "missing-gitignore",
                "No `.gitignore` file found in project root",
                Location::new(&gitignore_path, 0, 1),
                Severity::Error,
                Category::Gitignore,
            )
            .with_suggestion("Create a `.gitignore` file. Run `ignyt gitignore --init` or use gitignore.io for Python projects."),
        );
        print_results(&bag);
        return bag;
    }

    let content = match std::fs::read_to_string(&gitignore_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "  {} failed to read {}: {e}",
                "✗".red(),
                gitignore_path.display()
            );
            return bag;
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let active_patterns: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some((i + 1, trimmed))
            }
        })
        .collect();

    let pattern_set: HashSet<&str> = active_patterns.iter().map(|(_, p)| *p).collect();

    // GIT002: Missing essential Python patterns.
    check_missing_essential(&gitignore_path, &pattern_set, &mut bag);

    // GIT003: Duplicate entries.
    check_duplicates(&gitignore_path, &active_patterns, &mut bag);

    // GIT004: Invalid or problematic patterns.
    check_invalid_patterns(&gitignore_path, &lines, &mut bag);

    // GIT005: Overly broad patterns.
    check_overly_broad(&gitignore_path, &active_patterns, &mut bag);

    // GIT006: Missing secrets/env patterns.
    check_missing_secrets(&gitignore_path, &pattern_set, &mut bag);

    print_results(&bag);
    bag
}

/// GIT002: Check for missing essential Python patterns.
fn check_missing_essential(
    gitignore_path: &Path,
    patterns: &HashSet<&str>,
    bag: &mut DiagnosticBag,
) {
    let mut missing: Vec<(&str, &str)> = Vec::new();

    for &(pattern, desc) in ESSENTIAL_PYTHON_PATTERNS {
        // Check for exact match or common variations.
        let found = patterns.contains(pattern)
            || patterns.contains(pattern.trim_end_matches('/'))
            || (pattern == "*.pyc" && patterns.contains("__pycache__/"))
            || (pattern == "venv/" && (patterns.contains(".venv/") || patterns.contains(".venv")))
            || (pattern == ".env" && patterns.contains(".env*"));

        if !found {
            missing.push((pattern, desc));
        }
    }

    if !missing.is_empty() {
        let missing_list: Vec<String> = missing
            .iter()
            .map(|(p, d)| format!("`{p}` ({d})"))
            .collect();
        bag.push(
            Diagnostic::new(
                "GIT002",
                "missing-python-patterns",
                format!(
                    "Missing essential Python ignore patterns: {}",
                    missing_list.join(", ")
                ),
                Location::new(gitignore_path, 1, 1),
                Severity::Warning,
                Category::Gitignore,
            )
            .with_suggestion(format!(
                "Add these patterns to your .gitignore:\n{}",
                missing
                    .iter()
                    .map(|(p, _)| *p)
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        );
    }
}

/// GIT003: Check for duplicate entries.
fn check_duplicates(
    gitignore_path: &Path,
    active_patterns: &[(usize, &str)],
    bag: &mut DiagnosticBag,
) {
    let mut seen: HashSet<&str> = HashSet::new();

    for &(line_num, pattern) in active_patterns {
        if !seen.insert(pattern) {
            bag.push(
                Diagnostic::new(
                    "GIT003",
                    "duplicate-entry",
                    format!("Duplicate .gitignore entry: `{pattern}`"),
                    Location::new(gitignore_path, line_num, 1),
                    Severity::Hint,
                    Category::Gitignore,
                )
                .with_suggestion("Remove the duplicate line to keep .gitignore clean."),
            );
        }
    }
}

/// GIT004: Check for invalid or problematic patterns.
fn check_invalid_patterns(gitignore_path: &Path, lines: &[&str], bag: &mut DiagnosticBag) {
    for (i, line) in lines.iter().enumerate() {
        let line_num = i + 1;

        // Trailing whitespace on non-empty, non-comment lines.
        if !line.trim().is_empty() && !line.trim().starts_with('#') && line.ends_with(' ') {
            bag.push(
                Diagnostic::new(
                    "GIT004",
                    "trailing-whitespace",
                    format!("Trailing whitespace in pattern (line {line_num}) — may cause unexpected behavior"),
                    Location::new(gitignore_path, line_num, 1),
                    Severity::Warning,
                    Category::Gitignore,
                )
                .with_suggestion("Remove trailing spaces. Git treats trailing spaces as part of the pattern."),
            );
        }

        // Lines that are only whitespace (not truly empty).
        if !line.is_empty() && line.trim().is_empty() {
            bag.push(
                Diagnostic::new(
                    "GIT004",
                    "whitespace-only-line",
                    format!("Line {line_num} contains only whitespace — use a blank line instead"),
                    Location::new(gitignore_path, line_num, 1),
                    Severity::Hint,
                    Category::Gitignore,
                )
                .with_suggestion("Replace with an empty line or remove the whitespace."),
            );
        }

        // Patterns starting with a slash and containing wildcards in odd ways.
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Double asterisk misuse: `***` is invalid.
            if trimmed.contains("***") {
                bag.push(
                    Diagnostic::new(
                        "GIT004",
                        "invalid-glob",
                        format!("Invalid glob pattern `{trimmed}` — `***` is not a valid gitignore pattern"),
                        Location::new(gitignore_path, line_num, 1),
                        Severity::Error,
                        Category::Gitignore,
                    )
                    .with_suggestion("Use `**` to match across directories or `*` for single directory matches."),
                );
            }
        }
    }
}

/// GIT005: Check for overly broad patterns.
fn check_overly_broad(
    gitignore_path: &Path,
    active_patterns: &[(usize, &str)],
    bag: &mut DiagnosticBag,
) {
    for &(line_num, pattern) in active_patterns {
        // Skip negated patterns (these are intentional overrides).
        if pattern.starts_with('!') {
            continue;
        }

        for &(broad, reason) in OVERLY_BROAD_PATTERNS {
            if pattern == broad {
                bag.push(
                    Diagnostic::new(
                        "GIT005",
                        "overly-broad-pattern",
                        format!("Pattern `{pattern}` is too broad — {reason}"),
                        Location::new(gitignore_path, line_num, 1),
                        Severity::Error,
                        Category::Gitignore,
                    )
                    .with_suggestion("Remove this pattern or make it more specific (e.g., `build/*.py` instead of `*.py`)."),
                );
            }
        }

        // Catch `*` alone (ignores everything).
        if pattern == "*" {
            bag.push(
                Diagnostic::new(
                    "GIT005",
                    "overly-broad-pattern",
                    "Pattern `*` ignores ALL files — this is almost certainly a mistake",
                    Location::new(gitignore_path, line_num, 1),
                    Severity::Critical,
                    Category::Gitignore,
                )
                .with_suggestion("Remove `*` or use more specific patterns."),
            );
        }
    }
}

/// GIT006: Check for missing secrets/env patterns.
fn check_missing_secrets(gitignore_path: &Path, patterns: &HashSet<&str>, bag: &mut DiagnosticBag) {
    let mut missing_secrets: Vec<(&str, &str)> = Vec::new();

    for &(pattern, desc) in SECRETS_PATTERNS {
        let found = patterns.contains(pattern)
            || (pattern == ".env" && patterns.contains(".env*"))
            || (pattern == ".env.local"
                && (patterns.contains(".env*") || patterns.contains(".env.local")));

        if !found {
            missing_secrets.push((pattern, desc));
        }
    }

    if !missing_secrets.is_empty() {
        let missing_list: Vec<String> = missing_secrets
            .iter()
            .map(|(p, d)| format!("`{p}` ({d})"))
            .collect();
        bag.push(
            Diagnostic::new(
                "GIT006",
                "missing-secrets-pattern",
                format!(
                    "Missing secrets/env ignore patterns: {}",
                    missing_list.join(", ")
                ),
                Location::new(gitignore_path, 1, 1),
                Severity::Warning,
                Category::Gitignore,
            )
            .with_suggestion(format!(
                "Add these patterns to prevent accidental secret exposure:\n{}",
                missing_secrets
                    .iter()
                    .map(|(p, _)| *p)
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        );
    }
}

/// Generate a good default `.gitignore` for Python projects.
pub fn init_gitignore(project_path: &Path) {
    let gitignore_path = project_path.join(".gitignore");

    if gitignore_path.exists() {
        println!(
            "  {} .gitignore already exists at {}",
            "⚠".yellow(),
            gitignore_path.display()
        );
        return;
    }

    let content = r#"# Byte-compiled / optimized
__pycache__/
*.py[cod]
*$py.class
*.pyo

# Distribution / packaging
dist/
build/
*.egg-info/
*.egg
.eggs/

# Virtual environments
venv/
.venv/
ENV/

# Environment variables
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Testing / caching
.pytest_cache/
.mypy_cache/
.ruff_cache/
.tox/
.nox/
.hypothesis/
htmlcov/
.coverage
.coverage.*
coverage.xml

# Keys / secrets
*.pem
*.key

# OS files
.DS_Store
Thumbs.db
"#;

    match std::fs::write(&gitignore_path, content) {
        Ok(()) => {
            println!(
                "\n{} {} — created .gitignore\n",
                "✓".green().bold(),
                "Ignyt Gitignore".bold().cyan(),
            );
            println!("  Created {}", gitignore_path.display());
            println!("  Includes Python, virtual env, IDE, testing, and secrets patterns.");
            println!();
        }
        Err(e) => {
            eprintln!("  {} failed to create .gitignore: {e}", "✗".red());
        }
    }
}

fn print_results(bag: &DiagnosticBag) {
    if bag.is_empty() {
        println!(
            "  {} .gitignore looks good — no issues found\n",
            "✓".green().bold()
        );
    } else {
        for diag in bag.diagnostics() {
            let severity_str = match diag.severity {
                Severity::Hint => "hint".dimmed().to_string(),
                Severity::Warning => "warn".yellow().to_string(),
                Severity::Error => "error".red().to_string(),
                Severity::Critical => "CRITICAL".red().bold().to_string(),
            };
            println!(
                "  {} {} {}",
                diag.code.bold().cyan(),
                severity_str,
                diag.message
            );
            if let Some(ref suggestion) = diag.suggestion {
                // Only print first line of suggestion for compact output.
                if let Some(first_line) = suggestion.lines().next() {
                    println!("       {} {}", "→".dimmed(), first_line.dimmed());
                }
            }
        }
        println!(
            "\n  {} {} issue{} found\n",
            "⚠".yellow().bold(),
            bag.len(),
            if bag.len() == 1 { "" } else { "s" }
        );
    }
}
