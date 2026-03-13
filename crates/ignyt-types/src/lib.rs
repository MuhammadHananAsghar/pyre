//! # ignyt-types
//!
//! Type inference and checking engine for Ignyt. Reads type annotations,
//! builds control flow graphs for type narrowing, and reports type errors.
//!
//! This crate implements rules `TYPE001`–`TYPE007` (including `TYPE004`–`TYPE006`).

use ignyt_ast::SourceFile;
use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, IgnytResult, Severity};

/// Run type checking on a parsed source file.
///
/// Returns diagnostics for any type errors found.
pub fn check_types(file: &SourceFile) -> IgnytResult<DiagnosticBag> {
    let mut bag = DiagnosticBag::new();

    // Phase 1: Check for missing return type annotations on public functions.
    check_missing_annotations(file, &mut bag);

    // Phase 2: Check for missing return statements.
    check_missing_returns(file, &mut bag);

    // Phase 3: Check for incompatible default argument types.
    check_incompatible_defaults(file, &mut bag);

    // Phase 4: Check for unguarded Optional parameter access.
    check_optional_not_checked(file, &mut bag);

    // Phase 5: Check for redundant type casts.
    check_redundant_cast(file, &mut bag);

    // Phase 6: Check for mutable default arguments.
    check_mutable_default(file, &mut bag);

    // Phase 7: Check for redundant isinstance checks.
    check_redundant_isinstance(file, &mut bag);

    Ok(bag)
}

// ---------------------------------------------------------------------------
// TYPE003: Public functions missing return type annotations
// ---------------------------------------------------------------------------

/// TYPE003: Check for public functions missing type annotations.
fn check_missing_annotations(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let name = func.name.as_str();

            // Skip private functions (start with _).
            if name.starts_with('_') {
                continue;
            }

            // Check if return annotation is missing.
            if func.returns.is_none() {
                let location = file.location_from_range(&func.range);

                bag.push(
                    Diagnostic::new(
                        "TYPE003",
                        "missing-annotation",
                        format!("Public function `{name}` missing return type annotation"),
                        location,
                        Severity::Warning,
                        Category::Type,
                    )
                    .with_suggestion(format!("Add return type: `def {name}(...) -> ReturnType:`")),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE001: Missing return statement
// ---------------------------------------------------------------------------

/// Returns true if the return annotation is `-> None` (i.e., a `Name` node with id "None").
fn is_none_annotation(expr: &ignyt_ast::Expr) -> bool {
    use ignyt_ast::Expr;
    match expr {
        Expr::Constant(c) => matches!(c.value, ignyt_ast::Constant::None),
        Expr::Name(n) => n.id.as_str() == "None",
        _ => false,
    }
}

/// Scan a list of statements (but NOT nested function defs) for a `Return` with a value.
fn has_value_return(stmts: &[ignyt_ast::Stmt]) -> bool {
    use ignyt_ast::Stmt;

    for stmt in stmts {
        match stmt {
            Stmt::Return(ret) => {
                if ret.value.is_some() {
                    return true;
                }
            }
            // Recurse into control-flow blocks, but not nested function defs.
            Stmt::If(s) => {
                if has_value_return(&s.body) || has_value_return(&s.orelse) {
                    return true;
                }
            }
            Stmt::For(s) => {
                if has_value_return(&s.body) || has_value_return(&s.orelse) {
                    return true;
                }
            }
            Stmt::While(s) => {
                if has_value_return(&s.body) || has_value_return(&s.orelse) {
                    return true;
                }
            }
            Stmt::Try(s) => {
                if has_value_return(&s.body)
                    || has_value_return(&s.orelse)
                    || has_value_return(&s.finalbody)
                {
                    return true;
                }
            }
            Stmt::With(s) => {
                if has_value_return(&s.body) {
                    return true;
                }
            }
            // Do NOT recurse into nested function definitions.
            Stmt::FunctionDef(_) => {}
            _ => {}
        }
    }
    false
}

/// TYPE001: Detect functions with a return annotation (not `-> None`) but no `return <value>`.
fn check_missing_returns(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            // Only check functions that have a return annotation.
            let returns = match &func.returns {
                Some(r) => r,
                None => continue,
            };

            // Skip `-> None` annotations.
            if is_none_annotation(returns) {
                continue;
            }

            // If no value-bearing return exists, flag it.
            if !has_value_return(&func.body) {
                let name = func.name.as_str();
                let location = file.location_from_range(&func.range);

                bag.push(
                    Diagnostic::new(
                        "TYPE001",
                        "missing-return",
                        format!(
                            "Function `{name}` has a return type annotation but no `return` statement"
                        ),
                        location,
                        Severity::Error,
                        Category::Type,
                    )
                    .with_suggestion(
                        "Add a `return` statement or change the return type to `-> None`.",
                    ),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE002: Incompatible default argument type
// ---------------------------------------------------------------------------

/// Check whether a constant expression clearly conflicts with a simple type annotation.
///
/// Only the four primitive combinations called out in the spec are checked:
/// - `int` annotated with a string default
/// - `str` annotated with an integer default
/// - `bool` annotated with a string default
/// - `float` annotated with a string default
fn default_conflicts_with_annotation(
    annotation: &ignyt_ast::Expr,
    default: &ignyt_ast::Expr,
) -> bool {
    use ignyt_ast::{Constant, Expr};

    let ann_name = match annotation {
        Expr::Name(n) => n.id.as_str(),
        _ => return false,
    };

    let default_const = match default {
        Expr::Constant(c) => &c.value,
        _ => return false,
    };

    match ann_name {
        "int" => matches!(default_const, Constant::Str(_)),
        "str" => matches!(default_const, Constant::Int(_)),
        "bool" => matches!(default_const, Constant::Str(_)),
        "float" => matches!(default_const, Constant::Str(_)),
        _ => false,
    }
}

/// TYPE002: Detect parameters whose default value clearly conflicts with the type annotation.
fn check_incompatible_defaults(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let args = &func.args.args;

            for arg in args {
                let annotation = match &arg.def.annotation {
                    Some(a) => a,
                    None => continue,
                };
                let default = match &arg.default {
                    Some(d) => d,
                    None => continue,
                };

                if default_conflicts_with_annotation(annotation, default) {
                    let param_name = arg.def.arg.as_str();
                    let location = file.location_from_range(&func.range);

                    bag.push(
                        Diagnostic::new(
                            "TYPE002",
                            "incompatible-default",
                            format!(
                                "Parameter `{param_name}` has an incompatible default value type"
                            ),
                            location,
                            Severity::Error,
                            Category::Type,
                        )
                        .with_suggestion(
                            "Default value type does not match the parameter annotation.",
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE007: Optional not checked (None safety)
// ---------------------------------------------------------------------------

/// Check whether an annotation is `Optional[X]` (i.e., a Subscript with value Name("Optional")).
fn is_optional_annotation(annotation: &ignyt_ast::Expr) -> bool {
    use ignyt_ast::Expr;
    match annotation {
        Expr::Subscript(sub) => match sub.value.as_ref() {
            Expr::Name(n) => n.id.as_str() == "Optional",
            _ => false,
        },
        _ => false,
    }
}

/// Scan the body for any `if <param>` or `if <param> is not None` guard.
///
/// Returns `true` if at least one such guard exists at the top level of the body.
fn has_none_guard(stmts: &[ignyt_ast::Stmt], param: &str) -> bool {
    use ignyt_ast::{CmpOp, Expr, Stmt};

    for stmt in stmts {
        if let Stmt::If(if_stmt) = stmt {
            let test = &if_stmt.test;

            // `if param:` — a truthy check implicitly guards against None.
            if let Expr::Name(n) = test.as_ref() {
                if n.id.as_str() == param {
                    return true;
                }
            }

            // `if param is not None:` or `if param is None:` (any `is`/`is not` against None).
            if let Expr::Compare(cmp) = test.as_ref() {
                if let Expr::Name(n) = cmp.left.as_ref() {
                    if n.id.as_str() == param {
                        for (op, comparator) in cmp.ops.iter().zip(cmp.comparators.iter()) {
                            let is_none_comparator = match comparator {
                                Expr::Constant(c) => {
                                    matches!(c.value, ignyt_ast::Constant::None)
                                }
                                Expr::Name(n) => n.id.as_str() == "None",
                                _ => false,
                            };
                            if is_none_comparator && matches!(op, CmpOp::Is | CmpOp::IsNot) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Scan expressions (recursively) to find attribute accesses on `param`.
fn expr_has_attr_access_on(expr: &ignyt_ast::Expr, param: &str) -> bool {
    use ignyt_ast::Expr;

    match expr {
        Expr::Attribute(attr) => {
            // Direct `param.something`
            if let Expr::Name(n) = attr.value.as_ref() {
                if n.id.as_str() == param {
                    return true;
                }
            }
            expr_has_attr_access_on(&attr.value, param)
        }
        Expr::Call(call) => {
            if expr_has_attr_access_on(&call.func, param) {
                return true;
            }
            for arg in &call.args {
                if expr_has_attr_access_on(arg, param) {
                    return true;
                }
            }
            false
        }
        Expr::Subscript(sub) => {
            expr_has_attr_access_on(&sub.value, param) || expr_has_attr_access_on(&sub.slice, param)
        }
        Expr::BinOp(b) => {
            expr_has_attr_access_on(&b.left, param) || expr_has_attr_access_on(&b.right, param)
        }
        Expr::Compare(c) => {
            if expr_has_attr_access_on(&c.left, param) {
                return true;
            }
            c.comparators
                .iter()
                .any(|e| expr_has_attr_access_on(e, param))
        }
        _ => false,
    }
}

/// Scan a list of statements for attribute access on `param` (not inside a guard).
fn body_has_unguarded_attr_access(stmts: &[ignyt_ast::Stmt], param: &str) -> bool {
    use ignyt_ast::{Expr, Stmt};

    for stmt in stmts {
        match stmt {
            Stmt::Expr(e) => {
                if expr_has_attr_access_on(&e.value, param) {
                    return true;
                }
            }
            Stmt::Assign(a) => {
                if expr_has_attr_access_on(&a.value, param) {
                    return true;
                }
            }
            Stmt::AnnAssign(a) => {
                if let Some(val) = &a.value {
                    if expr_has_attr_access_on(val, param) {
                        return true;
                    }
                }
            }
            Stmt::Return(r) => {
                if let Some(val) = &r.value {
                    if expr_has_attr_access_on(val, param) {
                        return true;
                    }
                }
            }
            Stmt::If(if_stmt) => {
                // Check the test expression itself.
                if expr_has_attr_access_on(&if_stmt.test, param) {
                    return true;
                }
                // For the body of the if, only recurse if this if is NOT a guard for param.
                let is_guard = {
                    // `if param:` or `if param is not None:`
                    let test = &if_stmt.test;
                    let truthy_guard =
                        matches!(test.as_ref(), Expr::Name(n) if n.id.as_str() == param);
                    truthy_guard || {
                        if let Expr::Compare(cmp) = test.as_ref() {
                            matches!(cmp.left.as_ref(), Expr::Name(n) if n.id.as_str() == param)
                        } else {
                            false
                        }
                    }
                };
                if !is_guard {
                    if body_has_unguarded_attr_access(&if_stmt.body, param) {
                        return true;
                    }
                    if body_has_unguarded_attr_access(&if_stmt.orelse, param) {
                        return true;
                    }
                }
            }
            Stmt::For(f) => {
                if body_has_unguarded_attr_access(&f.body, param) {
                    return true;
                }
            }
            Stmt::While(w) => {
                if body_has_unguarded_attr_access(&w.body, param) {
                    return true;
                }
            }
            // Do not recurse into nested function definitions.
            Stmt::FunctionDef(_) => {}
            _ => {}
        }
    }
    false
}

/// TYPE007: Detect Optional parameters accessed without a None guard.
fn check_optional_not_checked(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            for arg in &func.args.args {
                let annotation = match &arg.def.annotation {
                    Some(a) => a,
                    None => continue,
                };

                if !is_optional_annotation(annotation) {
                    continue;
                }

                let param_name = arg.def.arg.as_str();

                // If there's already a guard in the top-level body, consider it safe.
                if has_none_guard(&func.body, param_name) {
                    continue;
                }

                // Check if the body accesses the param without a guard.
                if body_has_unguarded_attr_access(&func.body, param_name) {
                    let location = file.location_from_range(&func.range);

                    bag.push(
                        Diagnostic::new(
                            "TYPE007",
                            "none-not-checked",
                            format!(
                                "Parameter `{param_name}` is `Optional` but used without a `None` check"
                            ),
                            location,
                            Severity::Warning,
                            Category::Type,
                        )
                        .with_suggestion(
                            "Add a `None` check before accessing attributes on an `Optional` value.",
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE004: Redundant type cast
// ---------------------------------------------------------------------------

/// Collect parameter names and their simple type annotations from a function.
fn collect_param_annotations(func: &ignyt_ast::StmtFunctionDef) -> Vec<(&str, &str)> {
    use ignyt_ast::Expr;

    let mut params = Vec::new();
    for arg in &func.args.args {
        if let Some(annotation) = &arg.def.annotation {
            if let Expr::Name(n) = annotation.as_ref() {
                params.push((arg.def.arg.as_str(), n.id.as_str()));
            }
        }
    }
    params
}

/// The set of primitive cast functions we recognise.
const PRIMITIVE_CASTS: &[&str] = &["int", "str", "float", "bool"];

/// Scan an expression for redundant cast calls like `int(x)` where `x` is already `int`.
fn expr_has_redundant_cast(
    expr: &ignyt_ast::Expr,
    params: &[(&str, &str)],
) -> Option<(String, String)> {
    use ignyt_ast::Expr;

    match expr {
        Expr::Call(call) => {
            // Check if the call is `int(param)`, `str(param)`, etc.
            if let Expr::Name(func_name) = call.func.as_ref() {
                let cast_name = func_name.id.as_str();
                if PRIMITIVE_CASTS.contains(&cast_name) && call.args.len() == 1 {
                    if let Expr::Name(arg_name) = &call.args[0] {
                        let arg_id = arg_name.id.as_str();
                        for &(param, ann) in params {
                            if param == arg_id && ann == cast_name {
                                return Some((param.to_string(), ann.to_string()));
                            }
                        }
                    }
                }
            }
            // Recurse into call arguments.
            for arg in &call.args {
                if let Some(hit) = expr_has_redundant_cast(arg, params) {
                    return Some(hit);
                }
            }
            expr_has_redundant_cast(&call.func, params)
        }
        Expr::BinOp(b) => expr_has_redundant_cast(&b.left, params)
            .or_else(|| expr_has_redundant_cast(&b.right, params)),
        Expr::Compare(c) => {
            if let Some(hit) = expr_has_redundant_cast(&c.left, params) {
                return Some(hit);
            }
            c.comparators
                .iter()
                .find_map(|e| expr_has_redundant_cast(e, params))
        }
        _ => None,
    }
}

/// Scan statements for redundant cast expressions.
fn stmts_have_redundant_cast(
    stmts: &[ignyt_ast::Stmt],
    params: &[(&str, &str)],
) -> Option<(String, String)> {
    use ignyt_ast::Stmt;

    for stmt in stmts {
        match stmt {
            Stmt::Expr(e) => {
                if let Some(hit) = expr_has_redundant_cast(&e.value, params) {
                    return Some(hit);
                }
            }
            Stmt::Assign(a) => {
                if let Some(hit) = expr_has_redundant_cast(&a.value, params) {
                    return Some(hit);
                }
            }
            Stmt::AnnAssign(a) => {
                if let Some(val) = &a.value {
                    if let Some(hit) = expr_has_redundant_cast(val, params) {
                        return Some(hit);
                    }
                }
            }
            Stmt::Return(r) => {
                if let Some(val) = &r.value {
                    if let Some(hit) = expr_has_redundant_cast(val, params) {
                        return Some(hit);
                    }
                }
            }
            Stmt::If(s) => {
                if let Some(hit) = stmts_have_redundant_cast(&s.body, params) {
                    return Some(hit);
                }
                if let Some(hit) = stmts_have_redundant_cast(&s.orelse, params) {
                    return Some(hit);
                }
            }
            Stmt::For(s) => {
                if let Some(hit) = stmts_have_redundant_cast(&s.body, params) {
                    return Some(hit);
                }
            }
            Stmt::While(s) => {
                if let Some(hit) = stmts_have_redundant_cast(&s.body, params) {
                    return Some(hit);
                }
            }
            Stmt::FunctionDef(_) => {}
            _ => {}
        }
    }
    None
}

/// TYPE004: Detect redundant type casts like `int(x)` where `x` is already annotated as `int`.
fn check_redundant_cast(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let params = collect_param_annotations(func);
            if params.is_empty() {
                continue;
            }

            if let Some((param_name, type_name)) = stmts_have_redundant_cast(&func.body, &params) {
                let location = file.location_from_range(&func.range);

                bag.push(Diagnostic::new(
                    "TYPE004",
                    "redundant-cast",
                    format!(
                        "Redundant cast: `{type_name}({param_name})` — `{param_name}` is already annotated as `{type_name}`"
                    ),
                    location,
                    Severity::Hint,
                    Category::Type,
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE005: Mutable default argument
// ---------------------------------------------------------------------------

/// Check whether a default value expression is a mutable literal or constructor call.
///
/// Matches: `[]`, `{}`, `set()`, `list()`, `dict()`.
fn is_mutable_default(default: &ignyt_ast::Expr) -> bool {
    use ignyt_ast::Expr;

    match default {
        Expr::List(_) | Expr::Dict(_) | Expr::Set(_) => true,
        Expr::Call(call) => {
            if let Expr::Name(n) = call.func.as_ref() {
                let name = n.id.as_str();
                matches!(name, "set" | "list" | "dict") && call.args.is_empty()
            } else {
                false
            }
        }
        _ => false,
    }
}

/// TYPE005: Detect functions with mutable default arguments.
fn check_mutable_default(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            for arg in &func.args.args {
                let default = match &arg.default {
                    Some(d) => d,
                    None => continue,
                };

                if is_mutable_default(default) {
                    let param_name = arg.def.arg.as_str();
                    let location = file.location_from_range(&func.range);

                    bag.push(
                        Diagnostic::new(
                            "TYPE005",
                            "mutable-default",
                            format!("Parameter `{param_name}` has a mutable default argument"),
                            location,
                            Severity::Warning,
                            Category::Type,
                        )
                        .with_suggestion(
                            "Use `None` as default and initialize inside the function body.",
                        ),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TYPE006: Redundant isinstance check
// ---------------------------------------------------------------------------

/// Scan statements for `if isinstance(param, Type)` where param is annotated as Type.
fn find_redundant_isinstance(
    stmts: &[ignyt_ast::Stmt],
    params: &[(&str, &str)],
) -> Option<(String, String)> {
    use ignyt_ast::{Expr, Stmt};

    for stmt in stmts {
        if let Stmt::If(if_stmt) = stmt {
            if let Expr::Call(call) = if_stmt.test.as_ref() {
                if let Expr::Name(func_name) = call.func.as_ref() {
                    if func_name.id.as_str() == "isinstance" && call.args.len() == 2 {
                        if let (Expr::Name(obj), Expr::Name(typ)) = (&call.args[0], &call.args[1]) {
                            let obj_id = obj.id.as_str();
                            let typ_id = typ.id.as_str();
                            for &(param, ann) in params {
                                if param == obj_id && ann == typ_id {
                                    return Some((param.to_string(), ann.to_string()));
                                }
                            }
                        }
                    }
                }
            }
            // Recurse into if/else bodies.
            if let Some(hit) = find_redundant_isinstance(&if_stmt.body, params) {
                return Some(hit);
            }
            if let Some(hit) = find_redundant_isinstance(&if_stmt.orelse, params) {
                return Some(hit);
            }
        }
        // Recurse into other control-flow blocks but not nested functions.
        match stmt {
            Stmt::For(s) => {
                if let Some(hit) = find_redundant_isinstance(&s.body, params) {
                    return Some(hit);
                }
            }
            Stmt::While(s) => {
                if let Some(hit) = find_redundant_isinstance(&s.body, params) {
                    return Some(hit);
                }
            }
            Stmt::FunctionDef(_) => {}
            _ => {}
        }
    }
    None
}

/// TYPE006: Detect `isinstance(x, T)` where `x` is annotated as `T`, making the check always true.
fn check_redundant_isinstance(file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    for stmt in file.body() {
        if let Stmt::FunctionDef(func) = stmt {
            let params = collect_param_annotations(func);
            if params.is_empty() {
                continue;
            }

            if let Some((param_name, type_name)) = find_redundant_isinstance(&func.body, &params) {
                let location = file.location_from_range(&func.range);

                bag.push(Diagnostic::new(
                    "TYPE006",
                    "redundant-isinstance",
                    format!(
                        "Redundant check: `isinstance({param_name}, {type_name})` is always true — `{param_name}` is annotated as `{type_name}`"
                    ),
                    location,
                    Severity::Hint,
                    Category::Type,
                ));
            }
        }
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

    // -----------------------------------------------------------------------
    // TYPE003: missing return annotation
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_return_annotation() {
        let file = parse("def hello(name: str):\n    return f'Hello, {name}'");
        let bag = check_types(&file).unwrap();
        assert_eq!(bag.len(), 1);
        assert_eq!(bag.diagnostics()[0].code, "TYPE003");
    }

    #[test]
    fn test_annotated_function_passes() {
        let file = parse("def hello(name: str) -> str:\n    return f'Hello, {name}'");
        let bag = check_types(&file).unwrap();
        assert!(bag.is_empty());
    }

    #[test]
    fn test_private_function_skipped() {
        let file = parse("def _internal(x):\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(bag.is_empty());
    }

    // -----------------------------------------------------------------------
    // TYPE001: missing return statement
    // -----------------------------------------------------------------------

    #[test]
    fn test_type001_function_with_annotation_no_return_flagged() {
        // Has return annotation but no `return <value>` — should be flagged.
        let file = parse("def foo() -> int:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE001"),
            "expected TYPE001, got: {:?}",
            bag.diagnostics()
                .iter()
                .map(|d| &d.code)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_type001_function_with_annotation_and_return_passes() {
        // Has annotation AND a return statement — no TYPE001.
        let file = parse("def foo() -> int:\n    return 42");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE001"),
            "unexpected TYPE001"
        );
    }

    #[test]
    fn test_type001_none_annotation_no_return_passes() {
        // `-> None` with no return is fine.
        let file = parse("def foo() -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE001"),
            "unexpected TYPE001 on -> None function"
        );
    }

    #[test]
    fn test_type001_no_annotation_only_type003() {
        // No annotation at all — only TYPE003 should fire, not TYPE001.
        let file = parse("def foo():\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE001"),
            "TYPE001 should not fire when there is no annotation"
        );
        // TYPE003 should fire (public function, no annotation).
        assert!(bag.diagnostics().iter().any(|d| d.code == "TYPE003"));
    }

    // -----------------------------------------------------------------------
    // TYPE002: incompatible default argument type
    // -----------------------------------------------------------------------

    #[test]
    fn test_type002_int_with_string_default_flagged() {
        let file = parse("def foo(x: int = \"hello\") -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE002"),
            "expected TYPE002 for int param with string default"
        );
    }

    #[test]
    fn test_type002_int_with_int_default_passes() {
        let file = parse("def foo(x: int = 42) -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE002"),
            "unexpected TYPE002 for int param with int default"
        );
    }

    #[test]
    fn test_type002_str_with_int_default_flagged() {
        let file = parse("def foo(x: str = 123) -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE002"),
            "expected TYPE002 for str param with int default"
        );
    }

    // -----------------------------------------------------------------------
    // TYPE007: Optional not checked
    // -----------------------------------------------------------------------

    #[test]
    fn test_type007_optional_param_attr_access_no_guard_flagged() {
        // Accesses `.upper()` on an Optional[str] without a None check.
        let source =
            "from typing import Optional\ndef foo(x: Optional[str]) -> str:\n    return x.upper()";
        let file = parse(source);
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE007"),
            "expected TYPE007, got: {:?}",
            bag.diagnostics()
                .iter()
                .map(|d| &d.code)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_type007_optional_param_with_guard_passes() {
        // `if x is not None:` guards the attribute access — no TYPE007.
        let source = "from typing import Optional\ndef foo(x: Optional[str]) -> str:\n    if x is not None:\n        return x.upper()\n    return \"\"";
        let file = parse(source);
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE007"),
            "unexpected TYPE007 when guard is present"
        );
    }

    // -----------------------------------------------------------------------
    // TYPE004: redundant type cast
    // -----------------------------------------------------------------------

    #[test]
    fn test_type004_int_cast_on_int_param_flagged() {
        let file = parse("def foo(x: int) -> int:\n    return int(x)");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE004"),
            "expected TYPE004 for redundant int() cast, got: {:?}",
            bag.diagnostics()
                .iter()
                .map(|d| &d.code)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_type004_str_cast_on_int_param_passes() {
        // `str(x)` where x is `int` is a real conversion, not redundant.
        let file = parse("def foo(x: int) -> str:\n    return str(x)");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE004"),
            "unexpected TYPE004 for non-redundant str() cast"
        );
    }

    #[test]
    fn test_type004_str_cast_on_str_param_flagged() {
        let file = parse("def foo(name: str) -> str:\n    return str(name)");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE004"),
            "expected TYPE004 for redundant str() cast"
        );
    }

    // -----------------------------------------------------------------------
    // TYPE005: mutable default argument
    // -----------------------------------------------------------------------

    #[test]
    fn test_type005_list_default_flagged() {
        let file = parse("def foo(x: list = []) -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE005"),
            "expected TYPE005 for list default, got: {:?}",
            bag.diagnostics()
                .iter()
                .map(|d| &d.code)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_type005_dict_default_flagged() {
        let file = parse("def foo(x: dict = {}) -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE005"),
            "expected TYPE005 for dict default"
        );
    }

    #[test]
    fn test_type005_none_default_passes() {
        // `None` is an immutable default — no TYPE005.
        let file = parse("def foo(x: list = None) -> None:\n    pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE005"),
            "unexpected TYPE005 for None default"
        );
    }

    // -----------------------------------------------------------------------
    // TYPE006: redundant isinstance check
    // -----------------------------------------------------------------------

    #[test]
    fn test_type006_isinstance_same_type_flagged() {
        let file = parse("def foo(x: int) -> None:\n    if isinstance(x, int):\n        pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().any(|d| d.code == "TYPE006"),
            "expected TYPE006 for redundant isinstance, got: {:?}",
            bag.diagnostics()
                .iter()
                .map(|d| &d.code)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_type006_isinstance_different_type_passes() {
        let file = parse("def foo(x: int) -> None:\n    if isinstance(x, str):\n        pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE006"),
            "unexpected TYPE006 for different type isinstance check"
        );
    }

    #[test]
    fn test_type006_isinstance_no_annotation_passes() {
        let file = parse("def _foo(x) -> None:\n    if isinstance(x, int):\n        pass");
        let bag = check_types(&file).unwrap();
        assert!(
            bag.diagnostics().iter().all(|d| d.code != "TYPE006"),
            "unexpected TYPE006 when param has no annotation"
        );
    }
}
