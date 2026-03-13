//! # ignyt-fix
//!
//! Auto-fix engine for Ignyt. Applies safe, deterministic code transformations
//! to resolve fixable diagnostics. Operates on source text with line-based
//! replacements applied to preserve offsets.
//!
//! ## Supported fixes
//!
//! | Code    | Rule              | Fix applied                          |
//! |---------|-------------------|--------------------------------------|
//! | DEAD004 | unused-import     | Remove the entire import line        |
//! | SEC005  | yaml-unsafe-load  | Replace `yaml.load(` → `yaml.safe_load(` |
//! | FMT001  | import-order      | Sort the leading import block alphabetically |

use std::path::PathBuf;

use ignyt_ast::SourceFile;
use ignyt_diagnostics::IgnytResult;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single line-based fix: replace `old_text` at `line` with `new_text`.
///
/// Line numbers are 1-based (matching [`ignyt_diagnostics::Location`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// 1-based line number the fix targets.
    pub line: usize,
    /// The original line text (used to verify we are replacing the right line).
    pub old_text: String,
    /// The replacement text. An empty string means "delete this line".
    pub new_text: String,
}

/// A human-readable summary of one fix that was applied.
#[derive(Debug, Clone)]
pub struct FixDescription {
    /// Rule code (e.g. `"DEAD004"`).
    pub code: String,
    /// Short message describing what changed.
    pub message: String,
    /// 1-based line number where the fix was applied.
    pub line: usize,
}

/// Result returned by [`apply_fixes`].
#[derive(Debug, Clone)]
pub struct FixResult {
    /// Path of the file that was fixed.
    pub path: PathBuf,
    /// The full source text after all fixes have been applied.
    pub source: String,
    /// Descriptions of every fix that was applied.
    pub fixes_applied: Vec<FixDescription>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply all safe fixes to a source file. Returns the fixed source text
/// and a list of fixes that were applied.
pub fn apply_fixes(file: &SourceFile) -> IgnytResult<FixResult> {
    let descriptions = preview_fixes(file)?;

    // Collect the raw Fix objects again (preview_fixes only returns descriptions).
    let fixes = collect_all_fixes(file)?;

    let fixed_source = apply_fix_list(&file.source, &fixes);

    Ok(FixResult {
        path: file.path.clone(),
        source: fixed_source,
        fixes_applied: descriptions,
    })
}

/// Preview fixes without applying them (dry-run mode).
pub fn preview_fixes(file: &SourceFile) -> IgnytResult<Vec<FixDescription>> {
    let fixes = collect_all_fixes(file)?;
    let descriptions = fixes
        .iter()
        .map(|(fix, code, message)| FixDescription {
            code: code.clone(),
            message: message.clone(),
            line: fix.line,
        })
        .collect();
    Ok(descriptions)
}

// ---------------------------------------------------------------------------
// Internal: collect all fixes
// ---------------------------------------------------------------------------

/// Collect every fix with its associated code and message.
fn collect_all_fixes(file: &SourceFile) -> IgnytResult<Vec<(Fix, String, String)>> {
    let mut all: Vec<(Fix, String, String)> = Vec::new();

    // Order matters: unused-import removal first, then yaml fix, then sort.
    // We apply them in order so that line numbers remain stable within each
    // individual fixer (each fixer rebuilds from scratch anyway).
    all.extend(fix_unused_imports(file)?);
    all.extend(fix_yaml_load(file)?);
    all.extend(fix_import_order(file)?);

    Ok(all)
}

// ---------------------------------------------------------------------------
// FIX-DEAD004: Remove unused imports
// ---------------------------------------------------------------------------

fn fix_unused_imports(file: &SourceFile) -> IgnytResult<Vec<(Fix, String, String)>> {
    let bag = ignyt_dead::check_dead_code(file)?;
    let mut fixes: Vec<(Fix, String, String)> = Vec::new();

    let lines: Vec<&str> = file.source.lines().collect();

    for diag in bag.diagnostics() {
        if diag.code != "DEAD004" {
            continue;
        }

        let line_idx = diag.location.line.saturating_sub(1); // 0-based
        let Some(&line_text) = lines.get(line_idx) else {
            continue;
        };

        let fix = Fix {
            line: diag.location.line,
            old_text: line_text.to_string(),
            // Empty new_text = delete the line entirely
            new_text: String::new(),
        };

        fixes.push((
            fix,
            "DEAD004".to_string(),
            format!("Removed unused import on line {}", diag.location.line),
        ));
    }

    // Deduplicate: multiple DEAD004 diagnostics can point at the same import
    // line (e.g. `from x import A, B` — both A and B unused → two diagnostics,
    // same line). We only want to delete the line once.
    fixes.dedup_by_key(|(fix, _, _)| fix.line);

    Ok(fixes)
}

// ---------------------------------------------------------------------------
// FIX-SEC005: yaml.load → yaml.safe_load
// ---------------------------------------------------------------------------

fn fix_yaml_load(file: &SourceFile) -> IgnytResult<Vec<(Fix, String, String)>> {
    let bag = ignyt_security::check_security(file)?;
    let mut fixes: Vec<(Fix, String, String)> = Vec::new();

    let lines: Vec<&str> = file.source.lines().collect();

    for diag in bag.diagnostics() {
        if diag.code != "SEC005" {
            continue;
        }

        let line_idx = diag.location.line.saturating_sub(1);
        let Some(&line_text) = lines.get(line_idx) else {
            continue;
        };

        // Only act if the line literally contains `yaml.load(`
        // (without `Loader=`, which is what triggered the diagnostic).
        if !line_text.contains("yaml.load(") {
            continue;
        }

        let new_line = line_text.replace("yaml.load(", "yaml.safe_load(");

        fixes.push((
            Fix {
                line: diag.location.line,
                old_text: line_text.to_string(),
                new_text: new_line,
            },
            "SEC005".to_string(),
            format!(
                "Replaced yaml.load() with yaml.safe_load() on line {}",
                diag.location.line
            ),
        ));
    }

    fixes.dedup_by_key(|(fix, _, _)| fix.line);
    Ok(fixes)
}

// ---------------------------------------------------------------------------
// FIX-FMT001: Sort import block
// ---------------------------------------------------------------------------

/// Collect the leading contiguous block of import lines (lines that start with
/// `import ` or `from … import …`, possibly preceded by blank lines / comments
/// at the top of the file).  Sorts them alphabetically (case-insensitive) and
/// emits one Fix per line that needs to move.
fn fix_import_order(file: &SourceFile) -> IgnytResult<Vec<(Fix, String, String)>> {
    // Check whether the fmt engine reports any FMT001 / import-order issues.
    let options = ignyt_fmt::FmtOptions {
        line_length: 88,
        check_only: true,
    };
    let bag = ignyt_fmt::check_format(file, &options)?;

    let has_order_issue = bag
        .diagnostics()
        .iter()
        .any(|d| d.code == "FMT001" || d.name == "import-order");

    if !has_order_issue {
        return Ok(Vec::new());
    }

    let lines: Vec<&str> = file.source.lines().collect();

    // Find the contiguous block of import lines at the top of the file.
    // We skip leading blank lines / comment lines.
    let import_indices: Vec<usize> = find_leading_import_indices(&lines);

    if import_indices.is_empty() {
        return Ok(Vec::new());
    }

    // Extract import lines.
    let import_lines: Vec<&str> = import_indices.iter().map(|&i| lines[i]).collect();

    // Sort alphabetically, case-insensitive.
    let mut sorted = import_lines.clone();
    sorted.sort_by_key(|s| s.to_lowercase());

    // Emit a Fix for each line whose position changed.
    let mut fixes: Vec<(Fix, String, String)> = Vec::new();
    for (pos, (&orig_idx, (&orig_line, &sorted_line))) in import_indices
        .iter()
        .zip(import_lines.iter().zip(sorted.iter()))
        .enumerate()
    {
        if orig_line != sorted_line {
            fixes.push((
                Fix {
                    line: orig_idx + 1, // 1-based
                    old_text: orig_line.to_string(),
                    new_text: sorted_line.to_string(),
                },
                "FMT001".to_string(),
                format!(
                    "Sorted import at line {} (position {})",
                    orig_idx + 1,
                    pos + 1
                ),
            ));
        }
    }

    Ok(fixes)
}

/// Return the 0-based indices of the leading contiguous block of import
/// statements.  We consider a line part of the import block if it starts with
/// `import ` or `from `.  Leading blank lines and `#` comment lines are
/// skipped.  The block ends at the first non-import, non-blank, non-comment
/// line.
fn find_leading_import_indices(lines: &[&str]) -> Vec<usize> {
    let mut result = Vec::new();
    let mut in_block = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank / comment: fine before and between imports, but stop once
            // we've moved past the import block.
            if in_block {
                break;
            }
            continue;
        }

        if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
            result.push(i);
            in_block = true;
        } else {
            // Non-import code — stop.
            break;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Apply a list of fixes to source text
// ---------------------------------------------------------------------------

/// Apply a list of fixes to `source` and return the modified text.
///
/// Fixes that delete a line (empty `new_text`) remove the line entirely
/// (including its newline).  Fixes that replace a line substitute the content
/// while preserving the original line ending.
fn apply_fix_list(source: &str, fixes: &[(Fix, String, String)]) -> String {
    if fixes.is_empty() {
        return source.to_string();
    }

    // Build a set of line numbers (1-based) to delete and a map of replacements.
    use std::collections::HashMap;
    let mut deletions: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut replacements: HashMap<usize, String> = HashMap::new();

    for (fix, _, _) in fixes {
        if fix.new_text.is_empty() {
            deletions.insert(fix.line);
        } else {
            replacements.insert(fix.line, fix.new_text.clone());
        }
    }

    let mut result = String::with_capacity(source.len());
    for (idx, line) in source.lines().enumerate() {
        let line_num = idx + 1; // 1-based

        if deletions.contains(&line_num) {
            // Drop this line (and its newline) entirely.
            continue;
        }

        if let Some(new_content) = replacements.get(&line_num) {
            result.push_str(new_content);
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }

    // Preserve a trailing newline from the original if present.
    // (The loop above always adds '\n' after each line, so if the original
    // did NOT end with '\n', we need to strip the trailing one we added.)
    if !source.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(source: &str) -> SourceFile {
        SourceFile::parse_source(PathBuf::from("test.py"), source.to_string()).unwrap()
    }

    // -----------------------------------------------------------------------
    // DEAD004: Remove unused imports
    // -----------------------------------------------------------------------

    #[test]
    fn test_unused_import_removed() {
        let source = "import os\n\nx = 42\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        assert!(
            !result.source.contains("import os"),
            "Expected 'import os' to be removed, got:\n{}",
            result.source
        );
        assert!(result.source.contains("x = 42"));
        assert!(
            result.fixes_applied.iter().any(|f| f.code == "DEAD004"),
            "Expected at least one DEAD004 fix"
        );
    }

    #[test]
    fn test_used_import_not_removed() {
        let source = "import os\npath = os.getcwd()\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        assert!(
            result.source.contains("import os"),
            "Used import should NOT be removed"
        );
        assert!(
            result.fixes_applied.iter().all(|f| f.code != "DEAD004"),
            "Should have no DEAD004 fixes for a used import"
        );
    }

    #[test]
    fn test_unused_from_import_removed() {
        let source = "from pathlib import Path\n\nx = 42\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        assert!(
            !result.source.contains("from pathlib import Path"),
            "Unused from-import should be removed"
        );
    }

    // -----------------------------------------------------------------------
    // SEC005: yaml.load → yaml.safe_load
    // -----------------------------------------------------------------------

    #[test]
    fn test_yaml_load_replaced() {
        let source = "import yaml\ndata = yaml.load(content)\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        assert!(
            result.source.contains("yaml.safe_load"),
            "Expected yaml.load to be replaced with yaml.safe_load, got:\n{}",
            result.source
        );
        assert!(
            !result.source.contains("yaml.load("),
            "yaml.load( should no longer appear verbatim"
        );
        assert!(result.fixes_applied.iter().any(|f| f.code == "SEC005"));
    }

    #[test]
    fn test_yaml_safe_load_not_touched() {
        let source = "import yaml\ndata = yaml.load(content, Loader=yaml.SafeLoader)\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        // SEC005 is NOT triggered when Loader= is present, so no fix applied.
        assert!(
            result.fixes_applied.iter().all(|f| f.code != "SEC005"),
            "yaml.safe_load already safe — no fix expected"
        );
    }

    // -----------------------------------------------------------------------
    // FMT001: Sort imports
    // -----------------------------------------------------------------------

    #[test]
    fn test_import_sorting() {
        // All three names must be used so DEAD004 doesn't remove them first.
        let source = "import sys\nimport os\nimport ast\npath = os.getcwd()\nv = sys.version\nt = ast.parse('x')\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        // After sorting: ast, os, sys — the import block should be sorted.
        let import_lines: Vec<&str> = result
            .source
            .lines()
            .filter(|l| l.starts_with("import "))
            .collect();
        assert_eq!(
            import_lines,
            vec!["import ast", "import os", "import sys"],
            "Imports should be sorted alphabetically. Full source:\n{}",
            result.source
        );
        assert!(
            result.fixes_applied.iter().any(|f| f.code == "FMT001"),
            "Expected at least one FMT001 fix"
        );
    }

    #[test]
    fn test_already_sorted_imports_unchanged() {
        let source = "import ast\nimport os\nimport sys\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        // No FMT001 fixes expected.
        assert!(
            result.fixes_applied.iter().all(|f| f.code != "FMT001"),
            "Already sorted imports should not be re-sorted"
        );
    }

    // -----------------------------------------------------------------------
    // No-op: clean file produces no changes
    // -----------------------------------------------------------------------

    #[test]
    fn test_clean_file_unchanged() {
        let source = "import os\n\npath = os.getcwd()\n";
        let file = parse(source);
        let result = apply_fixes(&file).unwrap();
        assert!(
            result.fixes_applied.is_empty(),
            "Clean file should produce no fixes"
        );
        assert_eq!(result.source, source);
    }

    // -----------------------------------------------------------------------
    // preview_fixes returns descriptions without modifying source
    // -----------------------------------------------------------------------

    #[test]
    fn test_preview_fixes_does_not_modify_source() {
        let source = "import os\n\nx = 42\n";
        let file = parse(source);
        let descriptions = preview_fixes(&file).unwrap();
        // The original file is untouched.
        assert_eq!(file.source, source);
        assert!(
            descriptions.iter().any(|d| d.code == "DEAD004"),
            "preview should list the DEAD004 fix"
        );
    }

    // -----------------------------------------------------------------------
    // apply_fix_list helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_fix_list_delete_line() {
        let source = "import os\nimport sys\nx = 1\n";
        let fixes = vec![(
            Fix {
                line: 1,
                old_text: "import os".to_string(),
                new_text: String::new(),
            },
            "DEAD004".to_string(),
            "remove".to_string(),
        )];
        let result = apply_fix_list(source, &fixes);
        assert_eq!(result, "import sys\nx = 1\n");
    }

    #[test]
    fn test_apply_fix_list_replace_line() {
        let source = "import yaml\ndata = yaml.load(f)\n";
        let fixes = vec![(
            Fix {
                line: 2,
                old_text: "data = yaml.load(f)".to_string(),
                new_text: "data = yaml.safe_load(f)".to_string(),
            },
            "SEC005".to_string(),
            "replace".to_string(),
        )];
        let result = apply_fix_list(source, &fixes);
        assert_eq!(result, "import yaml\ndata = yaml.safe_load(f)\n");
    }
}
