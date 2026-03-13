//! # ignyt-dead
//!
//! Dead code and unused symbol detector for Ignyt. Builds a project-wide
//! symbol table, tracks references across files, and reports unused
//! functions, classes, variables, and imports with confidence scores.
//!
//! This crate implements rules `DEAD001`–`DEAD007`.

use ignyt_ast::{Ranged, SourceFile};
use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, IgnytResult, Severity};

/// Run dead code detection on a parsed source file.
///
/// Note: Full cross-file analysis requires a project-wide pass. This
/// single-file mode catches unused imports, unused local functions/variables,
/// and unreachable code.
pub fn check_dead_code(file: &SourceFile) -> IgnytResult<DiagnosticBag> {
    let mut bag = DiagnosticBag::new();

    check_unused_imports(file, &mut bag);
    check_unused_local_functions(file, &mut bag);
    check_unused_classes(file, &mut bag);
    check_unused_variables(file, &mut bag);
    check_unused_function_arguments(file, &mut bag);
    check_unreachable_code(file, &mut bag);

    Ok(bag)
}

// ---------------------------------------------------------------------------
// DEAD004: Unused imports
// ---------------------------------------------------------------------------

fn check_unused_imports(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let source = &file.source;

    for stmt in file.body() {
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    let used_name = alias
                        .asname
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or_else(|| alias.name.as_str());

                    if !is_name_used_beyond_import(source, used_name) {
                        let location = file.location_from_range(&import.range);
                        bag.push(
                            Diagnostic::new(
                                "DEAD004",
                                "unused-import",
                                format!("import {used_name} — never used"),
                                location,
                                Severity::Warning,
                                Category::Dead,
                            )
                            .with_fixable(true),
                        );
                    }
                }
            }
            Stmt::ImportFrom(import) => {
                for alias in &import.names {
                    let used_name = alias
                        .asname
                        .as_ref()
                        .map(|id| id.as_str())
                        .unwrap_or_else(|| alias.name.as_str());

                    if !is_name_used_beyond_import(source, used_name) {
                        let location = file.location_from_range(&import.range);
                        bag.push(
                            Diagnostic::new(
                                "DEAD004",
                                "unused-import",
                                format!("import {used_name} — never used"),
                                location,
                                Severity::Warning,
                                Category::Dead,
                            )
                            .with_fixable(true),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// DEAD001: Unused private functions (single-file, top-level)
// ---------------------------------------------------------------------------

fn check_unused_local_functions(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let source = &file.source;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let name = func.name.as_str();

            // Only flag private functions (start with _ but not __dunder__).
            if !name.starts_with('_') || name.starts_with("__") {
                continue;
            }

            // Check if the function name is used anywhere else in the source.
            if !is_name_used_beyond_import(source, name) {
                let location = file.location_from_range(&func.range);
                bag.push(
                    Diagnostic::new(
                        "DEAD001",
                        "unused-function",
                        format!("`{name}()` is defined but never called (90%)"),
                        location,
                        Severity::Warning,
                        Category::Dead,
                    )
                    .with_suggestion(format!("Remove `{name}` if it's no longer needed.")),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DEAD002: Unused private classes (single-file, top-level)
// ---------------------------------------------------------------------------

fn check_unused_classes(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let source = &file.source;

    for stmt in file.body() {
        if let Stmt::ClassDef(class) = stmt {
            let name = class.name.as_str();

            // Only flag private classes (start with _ but not __dunder__).
            if !name.starts_with('_') || name.starts_with("__") {
                continue;
            }

            // Check if the class name is used anywhere else in the source.
            if !is_name_used_beyond_import(source, name) {
                let location = file.location_from_range(&class.range);
                bag.push(
                    Diagnostic::new(
                        "DEAD002",
                        "unused-class",
                        format!("`{name}` is defined but never used (90%)"),
                        location,
                        Severity::Warning,
                        Category::Dead,
                    )
                    .with_suggestion(format!("Remove `{name}` if it's no longer needed.")),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DEAD003: Unused variables (single-file, top-level simple assignments)
// ---------------------------------------------------------------------------

fn check_unused_variables(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let source = &file.source;

    // Collect all top-level function bodies.
    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            check_unused_vars_in_body(&func.body, source, file, bag);
        }
    }
}

fn check_unused_vars_in_body(
    body: &[ignyt_ast::Stmt],
    source: &str,
    file: &SourceFile,
    bag: &mut DiagnosticBag,
) {
    use ignyt_ast::{Expr, Stmt};

    // Collect assignments, then check if the variable name appears beyond assignment.
    let mut assignments: Vec<(&str, &ignyt_ast::StmtAssign)> = Vec::new();

    for stmt in body {
        if let Stmt::Assign(assign) = stmt {
            for target in &assign.targets {
                if let Expr::Name(name) = target {
                    let var_name = name.id.as_str();
                    // Skip _ (conventional discard) and dunder names.
                    if var_name == "_" || var_name.starts_with("__") {
                        continue;
                    }
                    assignments.push((var_name, assign));
                }
            }
        }
    }

    // For each assignment, count uses in the function body text.
    // This is a rough heuristic — it works for obvious cases.
    for (var_name, assign) in &assignments {
        // Count all whole-word occurrences in the source.
        let count = count_whole_word_occurrences(source, var_name);

        // If it only appears once (the assignment itself), it's unused.
        if count <= 1 {
            let location = file.location_from_range(&assign.range);
            bag.push(Diagnostic::new(
                "DEAD003",
                "unused-variable",
                format!("`{var_name}` is assigned but never used"),
                location,
                Severity::Warning,
                Category::Dead,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// DEAD005: Unused function arguments
// ---------------------------------------------------------------------------

fn check_unused_function_arguments(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let name = func.name.as_str();

            // Only flag non-private (public API) functions.
            if name.starts_with('_') {
                continue;
            }

            // Skip functions with empty bodies (just `pass` or `...`).
            if is_empty_body(&func.body) {
                continue;
            }

            // Get the function body text from source.
            let body_start = func.body.first().map(|s| s.range().start());
            let body_end = func.body.last().map(|s| s.range().end());
            let body_text = match (body_start, body_end) {
                (Some(start), Some(end)) => {
                    let start_offset: usize = start.into();
                    let end_offset: usize = end.into();
                    if end_offset <= file.source.len() {
                        &file.source[start_offset..end_offset]
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            for arg in &func.args.args {
                let param_name = arg.def.arg.as_str();

                // Skip self, cls, _, and __dunder__ parameters.
                if param_name == "self"
                    || param_name == "cls"
                    || param_name == "_"
                    || (param_name.starts_with("__") && param_name.ends_with("__"))
                {
                    continue;
                }

                // Check if the parameter name appears in the function body text.
                if count_whole_word_occurrences(body_text, param_name) == 0 {
                    let location = file.location_from_range(&arg.def.range);
                    bag.push(
                        Diagnostic::new(
                            "DEAD005",
                            "unused-argument",
                            format!("argument `{param_name}` of `{name}()` is never used"),
                            location,
                            Severity::Hint,
                            Category::Dead,
                        )
                        .with_suggestion(format!(
                            "Prefix with `_` to indicate it's intentionally unused: `_{param_name}`"
                        )),
                    );
                }
            }
        }
    }
}

/// Check if a function body is empty (contains only `pass` or `...`).
fn is_empty_body(body: &[ignyt_ast::Stmt]) -> bool {
    use ignyt_ast::{Constant, Expr, Stmt};

    if body.len() != 1 {
        return false;
    }

    match &body[0] {
        Stmt::Pass(_) => true,
        Stmt::Expr(expr_stmt) => matches!(
            &*expr_stmt.value,
            Expr::Constant(c) if c.value == Constant::Ellipsis
        ),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// DEAD006: Unreachable code after return/raise/break/continue
// ---------------------------------------------------------------------------

fn check_unreachable_code(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            check_unreachable_in_body(&func.body, file, bag);
        }
    }
}

fn check_unreachable_in_body(body: &[ignyt_ast::Stmt], file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    let mut found_terminator = false;

    for stmt in body {
        if found_terminator {
            let location = file.location_from_range(&stmt.range());
            bag.push(Diagnostic::new(
                "DEAD006",
                "unreachable-code",
                "Code after `return`/`raise`/`break`/`continue` is unreachable",
                location,
                Severity::Warning,
                Category::Dead,
            ));
            return; // Only report the first unreachable statement.
        }

        match stmt {
            Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_) => {
                found_terminator = true;
            }
            // Recurse into nested blocks.
            Stmt::FunctionDef(f) => {
                check_unreachable_in_body(&f.body, file, bag);
            }
            Stmt::If(s) => {
                for child in &s.body {
                    if let Stmt::FunctionDef(f) = child {
                        check_unreachable_in_body(&f.body, file, bag);
                    }
                }
                check_unreachable_in_body(&s.body, file, bag);
                check_unreachable_in_body(&s.orelse, file, bag);
            }
            Stmt::For(s) => {
                check_unreachable_in_body(&s.body, file, bag);
            }
            Stmt::While(s) => {
                check_unreachable_in_body(&s.body, file, bag);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Count whole-word occurrences of `name` in `source`.
fn count_whole_word_occurrences(source: &str, name: &str) -> usize {
    source
        .match_indices(name)
        .filter(|(idx, _)| {
            let before = if *idx > 0 {
                source.as_bytes()[idx - 1]
            } else {
                b' '
            };
            let after_idx = idx + name.len();
            let after = if after_idx < source.len() {
                source.as_bytes()[after_idx]
            } else {
                b' '
            };
            !before.is_ascii_alphanumeric()
                && before != b'_'
                && !after.is_ascii_alphanumeric()
                && after != b'_'
        })
        .count()
}

/// Check if a name is used more than once in source (once = the import itself).
fn is_name_used_beyond_import(source: &str, name: &str) -> bool {
    count_whole_word_occurrences(source, name) > 1
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

    // DEAD004: unused imports
    #[test]
    fn test_unused_import_detected() {
        let file = parse("import os\n\nx = 42\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD004"));
        assert!(bag.diagnostics()[0].fixable);
    }

    #[test]
    fn test_used_import_not_flagged() {
        let file = parse("import os\n\npath = os.getcwd()\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD004"));
    }

    #[test]
    fn test_unused_from_import() {
        let file = parse("from pathlib import Path\n\nx = 42\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD004"));
    }

    #[test]
    fn test_used_from_import_not_flagged() {
        let file = parse("from pathlib import Path\n\np = Path('.')\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD004"));
    }

    // DEAD001: unused private functions
    #[test]
    fn test_unused_private_function() {
        let file = parse("def _helper():\n    return 42\n\ndef main():\n    pass\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD001"));
    }

    #[test]
    fn test_used_private_function_not_flagged() {
        let file = parse("def _helper():\n    return 42\n\nx = _helper()\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD001"));
    }

    #[test]
    fn test_public_function_not_flagged() {
        // Public functions might be called from other modules.
        let file = parse("def helper():\n    return 42\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD001"));
    }

    // DEAD006: unreachable code
    #[test]
    fn test_unreachable_after_return() {
        let file = parse("def foo():\n    return 1\n    x = 2\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD006"));
    }

    #[test]
    fn test_unreachable_after_raise() {
        let file = parse("def foo():\n    raise ValueError()\n    x = 2\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD006"));
    }

    #[test]
    fn test_no_unreachable_code() {
        let file = parse("def foo():\n    x = 1\n    return x\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD006"));
    }

    // DEAD003: unused variables
    #[test]
    fn test_unused_variable_in_function() {
        let file = parse("def foo():\n    unused_var = 42\n    return 0\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD003"));
    }

    #[test]
    fn test_used_variable_not_flagged() {
        let file = parse("def foo():\n    x = 42\n    return x\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD003"));
    }

    #[test]
    fn test_underscore_variable_not_flagged() {
        let file = parse("def foo():\n    _ = 42\n    return 0\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD003"));
    }

    // DEAD002: unused private classes
    #[test]
    fn test_unused_private_class() {
        let file = parse("class _Helper:\n    pass\n\ndef main():\n    pass\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "DEAD002"));
    }

    #[test]
    fn test_used_private_class_not_flagged() {
        let file = parse("class _Helper:\n    pass\n\nx = _Helper()\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD002"));
    }

    #[test]
    fn test_public_class_not_flagged() {
        let file = parse("class Helper:\n    pass\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD002"));
    }

    #[test]
    fn test_dunder_class_not_flagged() {
        let file = parse("class __Meta__:\n    pass\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD002"));
    }

    // DEAD005: unused function arguments
    #[test]
    fn test_unused_argument_detected() {
        let file = parse("def process(data, unused):\n    return data + 1\n");
        let bag = check_dead_code(&file).unwrap();
        let dead005: Vec<_> = bag
            .diagnostics()
            .iter()
            .filter(|d| d.code == "DEAD005")
            .collect();
        assert_eq!(dead005.len(), 1);
        assert!(dead005[0].message.contains("unused"));
    }

    #[test]
    fn test_used_argument_not_flagged() {
        let file = parse("def process(data, factor):\n    return data * factor\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD005"));
    }

    #[test]
    fn test_self_cls_not_flagged() {
        let file = parse("def method(self, cls, data):\n    return data\n");
        let bag = check_dead_code(&file).unwrap();
        let dead005: Vec<_> = bag
            .diagnostics()
            .iter()
            .filter(|d| d.code == "DEAD005")
            .collect();
        // self and cls should be skipped; only self and cls are unused but skipped
        assert!(dead005
            .iter()
            .all(|d| !d.message.contains("self") && !d.message.contains("cls")));
    }

    #[test]
    fn test_empty_body_not_flagged() {
        let file = parse("def stub(data, unused):\n    pass\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD005"));
    }

    #[test]
    fn test_ellipsis_body_not_flagged() {
        let file = parse("def stub(data, unused):\n    ...\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD005"));
    }

    #[test]
    fn test_private_function_args_not_flagged() {
        let file = parse("def _internal(data, unused):\n    return data\n");
        let bag = check_dead_code(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "DEAD005"));
    }
}
