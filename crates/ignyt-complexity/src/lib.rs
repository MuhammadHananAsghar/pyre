//! # ignyt-complexity
//!
//! Cyclomatic and cognitive complexity analyzer for Ignyt. Walks the AST
//! to compute complexity metrics for each function and reports violations
//! against configured thresholds.
//!
//! This crate implements rules `CMPLX001`–`CMPLX007`.

use ignyt_ast::SourceFile;
use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, IgnytResult, Severity};

/// Configuration thresholds for complexity checks.
#[derive(Debug, Clone)]
pub struct ComplexityThresholds {
    pub max_cyclomatic: usize,
    pub max_cognitive: usize,
    pub max_lines: usize,
    pub max_args: usize,
    pub max_branches: usize,
    pub max_nesting: usize,
    pub max_returns: usize,
}

impl Default for ComplexityThresholds {
    fn default() -> Self {
        Self {
            max_cyclomatic: 10,
            max_cognitive: 15,
            max_lines: 50,
            max_args: 5,
            max_branches: 12,
            max_nesting: 4,
            max_returns: 6,
        }
    }
}

/// Result of analyzing a single function's complexity.
#[derive(Debug)]
pub struct FunctionComplexity {
    pub name: String,
    pub start_offset: u32,
    pub end_offset: u32,
    pub cyclomatic: usize,
    pub cognitive: usize,
    pub arg_count: usize,
    pub branch_count: usize,
    pub max_nesting_depth: usize,
    pub return_count: usize,
}

/// Run complexity analysis on a parsed source file.
pub fn check_complexity(
    file: &SourceFile,
    thresholds: &ComplexityThresholds,
) -> IgnytResult<DiagnosticBag> {
    let mut bag = DiagnosticBag::new();

    for stmt in file.body() {
        if let ignyt_ast::Stmt::FunctionDef(func) = stmt {
            let metrics = analyze_function(func);
            report_violations(file, &metrics, thresholds, &mut bag);
        }
    }

    Ok(bag)
}

/// Analyze a single function definition and compute all complexity metrics.
fn analyze_function(func: &ignyt_ast::StmtFunctionDef) -> FunctionComplexity {
    let cyclomatic = compute_cyclomatic(&func.body);
    let cognitive = compute_cognitive(&func.body, 0);
    let branch_count = count_branches(&func.body);
    let max_nesting_depth = compute_max_nesting(&func.body, 0);
    let return_count = count_returns(&func.body);

    let arg_count = func.args.args.len() + func.args.posonlyargs.len() + func.args.kwonlyargs.len();

    FunctionComplexity {
        name: func.name.to_string(),
        start_offset: func.range.start().to_u32(),
        end_offset: func.range.end().to_u32(),
        cyclomatic,
        cognitive,
        arg_count,
        branch_count,
        max_nesting_depth,
        return_count,
    }
}

// ---------------------------------------------------------------------------
// Cyclomatic complexity
// ---------------------------------------------------------------------------

fn compute_cyclomatic(stmts: &[ignyt_ast::Stmt]) -> usize {
    let mut complexity = 1;
    for stmt in stmts {
        complexity += count_decisions(stmt);
    }
    complexity
}

fn count_decisions(stmt: &ignyt_ast::Stmt) -> usize {
    use ignyt_ast::Stmt;
    match stmt {
        Stmt::If(s) => {
            let mut count = 1;
            for s in &s.body {
                count += count_decisions(s);
            }
            for s in &s.orelse {
                count += count_decisions(s);
            }
            count
        }
        Stmt::For(s) => {
            let mut count = 1;
            for s in &s.body {
                count += count_decisions(s);
            }
            count
        }
        Stmt::While(s) => {
            let mut count = 1;
            for s in &s.body {
                count += count_decisions(s);
            }
            count
        }
        Stmt::Try(s) => {
            let mut count = s.handlers.len();
            for s in &s.body {
                count += count_decisions(s);
            }
            count
        }
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => 0,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Cognitive complexity
// ---------------------------------------------------------------------------

fn compute_cognitive(stmts: &[ignyt_ast::Stmt], nesting: usize) -> usize {
    let mut complexity = 0;
    for stmt in stmts {
        complexity += cognitive_for_stmt(stmt, nesting);
    }
    complexity
}

fn cognitive_for_stmt(stmt: &ignyt_ast::Stmt, nesting: usize) -> usize {
    use ignyt_ast::Stmt;
    match stmt {
        Stmt::If(s) => {
            let mut cost = 1 + nesting;
            cost += compute_cognitive(&s.body, nesting + 1);
            if !s.orelse.is_empty() {
                cost += 1;
                cost += compute_cognitive(&s.orelse, nesting + 1);
            }
            cost
        }
        Stmt::For(s) => {
            let mut cost = 1 + nesting;
            cost += compute_cognitive(&s.body, nesting + 1);
            cost
        }
        Stmt::While(s) => {
            let mut cost = 1 + nesting;
            cost += compute_cognitive(&s.body, nesting + 1);
            cost
        }
        Stmt::Try(s) => {
            let mut cost = 1 + nesting;
            cost += compute_cognitive(&s.body, nesting + 1);
            cost
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// CMPLX005: Branch count (if/elif chains)
// ---------------------------------------------------------------------------

fn count_branches(stmts: &[ignyt_ast::Stmt]) -> usize {
    let mut count = 0;
    for stmt in stmts {
        count += count_branches_in_stmt(stmt);
    }
    count
}

fn count_branches_in_stmt(stmt: &ignyt_ast::Stmt) -> usize {
    use ignyt_ast::Stmt;
    match stmt {
        Stmt::If(s) => {
            let mut count = 1; // The if branch itself
                               // Each elif/else is a branch
            if !s.orelse.is_empty() {
                count += 1;
            }
            count += count_branches(&s.body);
            count += count_branches(&s.orelse);
            count
        }
        Stmt::For(s) => count_branches(&s.body),
        Stmt::While(s) => count_branches(&s.body),
        Stmt::Try(s) => {
            let mut count = count_branches(&s.body);
            count += s.handlers.len(); // Each except is a branch
            count
        }
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => 0,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// CMPLX006: Max nesting depth
// ---------------------------------------------------------------------------

fn compute_max_nesting(stmts: &[ignyt_ast::Stmt], current_depth: usize) -> usize {
    let mut max_depth = current_depth;

    for stmt in stmts {
        let depth = nesting_depth_of(stmt, current_depth);
        if depth > max_depth {
            max_depth = depth;
        }
    }

    max_depth
}

fn nesting_depth_of(stmt: &ignyt_ast::Stmt, current_depth: usize) -> usize {
    use ignyt_ast::Stmt;
    match stmt {
        Stmt::If(s) => {
            let inner = current_depth + 1;
            let body_depth = compute_max_nesting(&s.body, inner);
            let else_depth = compute_max_nesting(&s.orelse, inner);
            body_depth.max(else_depth)
        }
        Stmt::For(s) => compute_max_nesting(&s.body, current_depth + 1),
        Stmt::While(s) => compute_max_nesting(&s.body, current_depth + 1),
        Stmt::Try(s) => compute_max_nesting(&s.body, current_depth + 1),
        Stmt::With(s) => compute_max_nesting(&s.body, current_depth + 1),
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => current_depth,
        _ => current_depth,
    }
}

// ---------------------------------------------------------------------------
// CMPLX007: Return count
// ---------------------------------------------------------------------------

fn count_returns(stmts: &[ignyt_ast::Stmt]) -> usize {
    let mut count = 0;
    for stmt in stmts {
        count += returns_in_stmt(stmt);
    }
    count
}

fn returns_in_stmt(stmt: &ignyt_ast::Stmt) -> usize {
    use ignyt_ast::Stmt;
    match stmt {
        Stmt::Return(_) => 1,
        Stmt::If(s) => count_returns(&s.body) + count_returns(&s.orelse),
        Stmt::For(s) => count_returns(&s.body),
        Stmt::While(s) => count_returns(&s.body),
        Stmt::Try(s) => count_returns(&s.body) + count_returns(&s.finalbody),
        Stmt::With(s) => count_returns(&s.body),
        Stmt::FunctionDef(_) | Stmt::ClassDef(_) => 0, // Don't count nested function returns
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Violation reporting
// ---------------------------------------------------------------------------

fn report_violations(
    file: &SourceFile,
    metrics: &FunctionComplexity,
    thresholds: &ComplexityThresholds,
    bag: &mut DiagnosticBag,
) {
    let location = || file.location_from_offset(metrics.start_offset);

    let start_line = file
        .source_map
        .offset_to_line_col(metrics.start_offset as usize)
        .map(|(l, _)| l)
        .unwrap_or(1);
    let end_line = file
        .source_map
        .offset_to_line_col(metrics.end_offset as usize)
        .map(|(l, _)| l)
        .unwrap_or(1);
    let line_count = end_line.saturating_sub(start_line) + 1;

    if metrics.cyclomatic > thresholds.max_cyclomatic {
        bag.push(Diagnostic::new(
            "CMPLX001",
            "high-cyclomatic",
            format!(
                "`{}()` cyclomatic complexity: {} (limit: {})",
                metrics.name, metrics.cyclomatic, thresholds.max_cyclomatic
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if metrics.cognitive > thresholds.max_cognitive {
        bag.push(Diagnostic::new(
            "CMPLX002",
            "high-cognitive",
            format!(
                "`{}()` cognitive complexity: {} (limit: {})",
                metrics.name, metrics.cognitive, thresholds.max_cognitive
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if metrics.arg_count > thresholds.max_args {
        bag.push(Diagnostic::new(
            "CMPLX003",
            "too-many-args",
            format!(
                "`{}()` has {} parameters (limit: {})",
                metrics.name, metrics.arg_count, thresholds.max_args
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if line_count > thresholds.max_lines {
        bag.push(Diagnostic::new(
            "CMPLX004",
            "too-many-lines",
            format!(
                "`{}()` is {} lines long (limit: {})",
                metrics.name, line_count, thresholds.max_lines
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if metrics.branch_count > thresholds.max_branches {
        bag.push(Diagnostic::new(
            "CMPLX005",
            "too-many-branches",
            format!(
                "`{}()` has {} branches (limit: {})",
                metrics.name, metrics.branch_count, thresholds.max_branches
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if metrics.max_nesting_depth > thresholds.max_nesting {
        bag.push(Diagnostic::new(
            "CMPLX006",
            "too-deeply-nested",
            format!(
                "`{}()` is nested {} levels deep (limit: {})",
                metrics.name, metrics.max_nesting_depth, thresholds.max_nesting
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }

    if metrics.return_count > thresholds.max_returns {
        bag.push(Diagnostic::new(
            "CMPLX007",
            "too-many-returns",
            format!(
                "`{}()` has {} return statements (limit: {})",
                metrics.name, metrics.return_count, thresholds.max_returns
            ),
            location(),
            Severity::Warning,
            Category::Complexity,
        ));
    }
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

    #[test]
    fn test_simple_function_low_complexity() {
        let file = parse("def simple():\n    return 42\n");
        let bag = check_complexity(&file, &ComplexityThresholds::default()).unwrap();
        assert!(bag.is_empty());
    }

    #[test]
    fn test_complex_function_detected() {
        let source = r#"
def complex_func(x):
    if x > 0:
        if x > 10:
            if x > 100:
                return "big"
            elif x > 50:
                return "medium-big"
            else:
                return "medium"
        else:
            return "small"
    elif x == 0:
        return "zero"
    else:
        if x < -10:
            return "very negative"
        else:
            return "negative"
"#;
        let file = parse(source);
        let thresholds = ComplexityThresholds {
            max_cyclomatic: 3,
            ..Default::default()
        };
        let bag = check_complexity(&file, &thresholds).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX001"));
    }

    #[test]
    fn test_too_many_args() {
        let source = "def many_args(a, b, c, d, e, f, g):\n    pass\n";
        let file = parse(source);
        let bag = check_complexity(&file, &ComplexityThresholds::default()).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX003"));
    }

    #[test]
    fn test_cognitive_complexity_with_nesting() {
        let source = r#"
def nested(x):
    if x:
        for i in range(10):
            if i > 5:
                while True:
                    break
"#;
        let file = parse(source);
        let thresholds = ComplexityThresholds {
            max_cognitive: 3,
            ..Default::default()
        };
        let bag = check_complexity(&file, &thresholds).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX002"));
    }

    // CMPLX005: too many branches
    #[test]
    fn test_too_many_branches() {
        let source = r#"
def branchy(x):
    if x == 1:
        pass
    elif x == 2:
        pass
    elif x == 3:
        pass
    elif x == 4:
        pass
    elif x == 5:
        pass
    elif x == 6:
        pass
    elif x == 7:
        pass
    elif x == 8:
        pass
    elif x == 9:
        pass
    elif x == 10:
        pass
    elif x == 11:
        pass
    elif x == 12:
        pass
    elif x == 13:
        pass
    else:
        pass
"#;
        let file = parse(source);
        let thresholds = ComplexityThresholds {
            max_branches: 5,
            ..Default::default()
        };
        let bag = check_complexity(&file, &thresholds).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX005"));
    }

    // CMPLX006: too deeply nested
    #[test]
    fn test_too_deeply_nested() {
        let source = r#"
def deep(x):
    if x:
        for i in range(10):
            if i > 0:
                while True:
                    if i > 5:
                        break
"#;
        let file = parse(source);
        let thresholds = ComplexityThresholds {
            max_nesting: 3,
            ..Default::default()
        };
        let bag = check_complexity(&file, &thresholds).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX006"));
    }

    #[test]
    fn test_shallow_nesting_ok() {
        let file = parse("def flat():\n    if True:\n        pass\n");
        let bag = check_complexity(&file, &ComplexityThresholds::default()).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "CMPLX006"));
    }

    // CMPLX007: too many returns
    #[test]
    fn test_too_many_returns() {
        let source = r#"
def many_returns(x):
    if x == 1:
        return 1
    elif x == 2:
        return 2
    elif x == 3:
        return 3
    elif x == 4:
        return 4
    elif x == 5:
        return 5
    elif x == 6:
        return 6
    else:
        return 7
"#;
        let file = parse(source);
        let bag = check_complexity(&file, &ComplexityThresholds::default()).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "CMPLX007"));
    }

    #[test]
    fn test_few_returns_ok() {
        let file = parse("def foo(x):\n    if x:\n        return 1\n    return 0\n");
        let bag = check_complexity(&file, &ComplexityThresholds::default()).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "CMPLX007"));
    }
}
