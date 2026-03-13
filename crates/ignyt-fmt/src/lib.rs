//! # ignyt-fmt
//!
//! Code formatter and import sorter for Ignyt. Handles import reordering
//! (isort replacement), unused import removal (autoflake replacement),
//! and code formatting.

use ignyt_ast::SourceFile;
use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, IgnytResult, Location, Severity};

/// Formatter configuration.
#[derive(Debug, Clone)]
pub struct FmtOptions {
    pub line_length: usize,
    pub check_only: bool,
}

impl Default for FmtOptions {
    fn default() -> Self {
        Self {
            line_length: 88,
            check_only: true,
        }
    }
}

/// Check formatting of a parsed source file.
pub fn check_format(file: &SourceFile, options: &FmtOptions) -> IgnytResult<DiagnosticBag> {
    let mut bag = DiagnosticBag::new();

    check_import_order(file, &mut bag);
    check_line_length(file, options, &mut bag);

    Ok(bag)
}

/// Check that imports are properly sorted alphabetically.
fn check_import_order(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let mut import_groups: Vec<(u32, String)> = Vec::new();

    for stmt in file.body() {
        match stmt {
            Stmt::Import(imp) => {
                for alias in &imp.names {
                    import_groups.push((imp.range.start().to_u32(), alias.name.to_string()));
                }
            }
            Stmt::ImportFrom(imp) => {
                if let Some(module) = &imp.module {
                    import_groups.push((imp.range.start().to_u32(), module.to_string()));
                }
            }
            _ => {}
        }
    }

    for window in import_groups.windows(2) {
        let (offset_a, name_a) = &window[0];
        let (_offset_b, name_b) = &window[1];

        if name_a.to_lowercase() > name_b.to_lowercase() {
            let location = file.location_from_offset(*offset_a);
            bag.push(
                Diagnostic::new(
                    "FMT001",
                    "unsorted-imports",
                    format!("Import `{name_a}` should come after `{name_b}` (alphabetical order)"),
                    location,
                    Severity::Hint,
                    Category::Format,
                )
                .with_fixable(true),
            );
            break;
        }
    }
}

/// Check for lines exceeding the configured max length.
fn check_line_length(file: &SourceFile, options: &FmtOptions, bag: &mut DiagnosticBag) {
    for (line_num, line) in file.source.lines().enumerate() {
        if line.len() > options.line_length {
            let location = Location::new(&file.path, line_num + 1, options.line_length + 1);
            bag.push(
                Diagnostic::new(
                    "FMT002",
                    "line-too-long",
                    format!(
                        "Line is {} characters (limit: {})",
                        line.len(),
                        options.line_length
                    ),
                    location,
                    Severity::Hint,
                    Category::Format,
                )
                .with_fixable(false),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(source: &str) -> SourceFile {
        SourceFile::parse_source(PathBuf::from("test.py"), source.to_string()).unwrap()
    }

    #[test]
    fn test_sorted_imports_ok() {
        let file = parse("import ast\nimport os\nimport sys\n");
        let bag = check_format(&file, &FmtOptions::default()).unwrap();
        let import_diags: Vec<_> = bag
            .diagnostics()
            .iter()
            .filter(|d| d.code == "FMT001")
            .collect();
        assert!(import_diags.is_empty());
    }

    #[test]
    fn test_unsorted_imports_detected() {
        let file = parse("import sys\nimport os\nimport ast\n");
        let bag = check_format(&file, &FmtOptions::default()).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "FMT001"));
    }

    #[test]
    fn test_line_too_long() {
        let long_line = format!("x = '{}'\n", "a".repeat(100));
        let file = parse(&long_line);
        let options = FmtOptions {
            line_length: 88,
            check_only: true,
        };
        let bag = check_format(&file, &options).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "FMT002"));
    }

    #[test]
    fn test_short_lines_ok() {
        let file = parse("x = 42\ny = 'hello'\n");
        let bag = check_format(&file, &FmtOptions::default()).unwrap();
        let line_diags: Vec<_> = bag
            .diagnostics()
            .iter()
            .filter(|d| d.code == "FMT002")
            .collect();
        assert!(line_diags.is_empty());
    }
}
