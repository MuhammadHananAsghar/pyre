//! # ignyt-security
//!
//! Security scanner for Ignyt. Performs AST pattern matching for common
//! security anti-patterns (SEC001–SEC012) and CVE auditing via the OSV
//! database.
//!
//! Two-layer approach:
//! - **Layer 1**: Static AST pattern matching (this module)
//! - **Layer 2**: Dependency CVE auditing (planned)

use ignyt_ast::SourceFile;
use ignyt_diagnostics::{Category, Diagnostic, DiagnosticBag, IgnytResult, Location, Severity};

/// Run security analysis on a parsed source file.
pub fn check_security(file: &SourceFile) -> IgnytResult<DiagnosticBag> {
    let mut bag = DiagnosticBag::new();

    // Walk all statements recursively, checking every expression.
    for stmt in file.body() {
        visit_stmt(stmt, file, &mut bag);
    }

    // Line-based heuristics for patterns hard to detect via AST alone.
    check_shell_injection(file, &mut bag);
    check_xml_import(file, &mut bag);
    check_debug_enabled(file, &mut bag);

    Ok(bag)
}

// ---------------------------------------------------------------------------
// Recursive AST visitor
// ---------------------------------------------------------------------------

fn visit_stmt(stmt: &ignyt_ast::Stmt, file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    // Check expressions embedded in this statement.
    visit_stmt_exprs(stmt, file, bag);

    // Check statement-level rules.
    check_assert_usage(stmt, file, bag);

    // Recurse into child statements.
    match stmt {
        Stmt::FunctionDef(f) => {
            for s in &f.body {
                visit_stmt(s, file, bag);
            }
        }
        Stmt::ClassDef(c) => {
            for s in &c.body {
                visit_stmt(s, file, bag);
            }
        }
        Stmt::If(s) => {
            for child in &s.body {
                visit_stmt(child, file, bag);
            }
            for child in &s.orelse {
                visit_stmt(child, file, bag);
            }
        }
        Stmt::For(s) => {
            for child in &s.body {
                visit_stmt(child, file, bag);
            }
            for child in &s.orelse {
                visit_stmt(child, file, bag);
            }
        }
        Stmt::While(s) => {
            for child in &s.body {
                visit_stmt(child, file, bag);
            }
            for child in &s.orelse {
                visit_stmt(child, file, bag);
            }
        }
        Stmt::Try(s) => {
            for child in &s.body {
                visit_stmt(child, file, bag);
            }
            for handler in &s.handlers {
                let ignyt_ast::ExceptHandler::ExceptHandler(h) = handler;
                for child in &h.body {
                    visit_stmt(child, file, bag);
                }
            }
            for child in &s.orelse {
                visit_stmt(child, file, bag);
            }
            for child in &s.finalbody {
                visit_stmt(child, file, bag);
            }
        }
        Stmt::With(s) => {
            for child in &s.body {
                visit_stmt(child, file, bag);
            }
        }
        _ => {}
    }
}

/// Extract and check all expressions from a statement.
fn visit_stmt_exprs(stmt: &ignyt_ast::Stmt, file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    match stmt {
        Stmt::Expr(s) => visit_expr(&s.value, file, bag),
        Stmt::Assign(s) => {
            visit_expr(&s.value, file, bag);
            // SEC001: check for hardcoded passwords in assignments.
            check_hardcoded_password(s, file, bag);
            // SEC009: check for hardcoded tokens/API keys in assignments.
            check_hardcoded_token(s, file, bag);
            // SEC002: check for .format() calls on SQL-keyword strings.
            check_sql_injection_format_assign(s, file, bag);
        }
        Stmt::AnnAssign(s) => {
            if let Some(ref value) = s.value {
                visit_expr(value, file, bag);
            }
        }
        Stmt::Return(s) => {
            if let Some(ref value) = s.value {
                visit_expr(value, file, bag);
            }
        }
        Stmt::AugAssign(s) => {
            visit_expr(&s.value, file, bag);
        }
        _ => {}
    }
}

/// Recursively visit an expression tree looking for dangerous calls.
fn visit_expr(expr: &ignyt_ast::Expr, file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Expr;

    match expr {
        Expr::Call(call) => {
            check_dangerous_call(call, file, bag);
            // Also visit arguments — they may contain nested calls.
            visit_expr(&call.func, file, bag);
            for arg in &call.args {
                visit_expr(arg, file, bag);
            }
            for kw in &call.keywords {
                visit_expr(&kw.value, file, bag);
            }
        }
        Expr::BoolOp(op) => {
            for value in &op.values {
                visit_expr(value, file, bag);
            }
        }
        Expr::BinOp(op) => {
            // SEC002: string concatenation used to build SQL queries.
            check_sql_injection_binop(op, file, bag);
            visit_expr(&op.left, file, bag);
            visit_expr(&op.right, file, bag);
        }
        Expr::UnaryOp(op) => {
            visit_expr(&op.operand, file, bag);
        }
        Expr::IfExp(e) => {
            visit_expr(&e.test, file, bag);
            visit_expr(&e.body, file, bag);
            visit_expr(&e.orelse, file, bag);
        }
        Expr::List(l) => {
            for elt in &l.elts {
                visit_expr(elt, file, bag);
            }
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                visit_expr(elt, file, bag);
            }
        }
        Expr::Dict(d) => {
            for key in d.keys.iter().flatten() {
                visit_expr(key, file, bag);
            }
            for val in &d.values {
                visit_expr(val, file, bag);
            }
        }
        Expr::Attribute(attr) => {
            // Recurse into the receiver so chained calls like
            // `hashlib.md5(data).hexdigest()` visit the inner call.
            visit_expr(&attr.value, file, bag);
        }
        // SEC002: f-strings used to build SQL queries.
        Expr::JoinedStr(fstr) => {
            check_sql_injection_fstring(fstr, file, bag);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

/// SEC011: eval/exec usage. SEC005: yaml.load. SEC008: weak crypto. SEC004: pickle.
fn check_dangerous_call(call: &ignyt_ast::ExprCall, file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Expr;

    // Simple name calls: eval(), exec(), open(), etc.
    if let Expr::Name(name) = call.func.as_ref() {
        let func_name = name.id.as_str();
        if func_name == "eval" || func_name == "exec" {
            bag.push(
                Diagnostic::new(
                    "SEC011",
                    "eval-usage",
                    format!("`{func_name}()` can execute arbitrary code"),
                    file.location_from_range(&name.range),
                    Severity::Critical,
                    Category::Security,
                )
                .with_suggestion(format!(
                    "Avoid `{func_name}()` with external input. Use `ast.literal_eval()` for safe parsing."
                )),
            );
        }

        // SEC012: open() with a variable (non-literal) path — potential path traversal.
        if func_name == "open" {
            if let Some(first_arg) = call.args.first() {
                if matches!(first_arg, Expr::Name(_)) {
                    bag.push(
                        Diagnostic::new(
                            "SEC012",
                            "path-traversal",
                            "`open()` called with a variable path — potential path traversal",
                            file.location_from_range(&name.range),
                            Severity::Warning,
                            Category::Security,
                        )
                        .with_suggestion(
                            "Validate and sanitize file paths. Use `os.path.realpath()` and check against an allowed base directory.",
                        ),
                    );
                }
            }
        }
    }

    // Attribute calls: yaml.load(), pickle.loads(), hashlib.md5(), etc.
    if let Expr::Attribute(attr) = call.func.as_ref() {
        let method = attr.attr.as_str();

        // SEC005: yaml.load() without SafeLoader
        if method == "load" {
            if let Expr::Name(obj) = attr.value.as_ref() {
                if obj.id.as_str() == "yaml" {
                    let has_safe_loader = call
                        .keywords
                        .iter()
                        .any(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "Loader"));
                    if !has_safe_loader && call.args.len() <= 1 {
                        bag.push(
                            Diagnostic::new(
                                "SEC005",
                                "yaml-unsafe-load",
                                "`yaml.load()` without `Loader=SafeLoader` allows arbitrary code execution",
                                file.location_from_range(&attr.range),
                                Severity::Critical,
                                Category::Security,
                            )
                            .with_suggestion("Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.")
                            .with_fixable(true),
                        );
                    }
                }
            }
        }

        // SEC004: pickle.loads() / pickle.load()
        if method == "loads" || method == "load" {
            if let Expr::Name(obj) = attr.value.as_ref() {
                if obj.id.as_str() == "pickle" {
                    bag.push(
                        Diagnostic::new(
                            "SEC004",
                            "pickle-usage",
                            format!("`pickle.{method}()` can execute arbitrary code during deserialization"),
                            file.location_from_range(&attr.range),
                            Severity::Critical,
                            Category::Security,
                        )
                        .with_suggestion("Avoid `pickle` for untrusted data. Use `json` or `msgpack` instead."),
                    );
                }
            }
        }

        // SEC008: weak crypto — hashlib.md5(), hashlib.sha1()
        if method == "md5" || method == "sha1" {
            if let Expr::Name(obj) = attr.value.as_ref() {
                if obj.id.as_str() == "hashlib" {
                    bag.push(
                        Diagnostic::new(
                            "SEC008",
                            "weak-crypto",
                            format!("`hashlib.{method}()` is cryptographically weak"),
                            file.location_from_range(&attr.range),
                            Severity::Warning,
                            Category::Security,
                        )
                        .with_suggestion(
                            "Use `hashlib.sha256()` or `bcrypt` for security-sensitive hashing.",
                        ),
                    );
                }
            }
        }

        // SEC012: os.path.join() with a variable argument — potential path traversal.
        if method == "join" {
            if let Expr::Attribute(path_attr) = attr.value.as_ref() {
                if path_attr.attr.as_str() == "path" {
                    if let Expr::Name(obj) = path_attr.value.as_ref() {
                        if obj.id.as_str() == "os" {
                            let has_variable_arg =
                                call.args.iter().any(|arg| matches!(arg, Expr::Name(_)));
                            if has_variable_arg {
                                bag.push(
                                    Diagnostic::new(
                                        "SEC012",
                                        "path-traversal",
                                        "`os.path.join()` called with a variable argument — potential path traversal",
                                        file.location_from_range(&attr.range),
                                        Severity::Warning,
                                        Category::Security,
                                    )
                                    .with_suggestion(
                                        "Validate and sanitize file paths. Use `os.path.realpath()` and check against an allowed base directory.",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        // SEC006: XML External Entity (XXE) / XML Bomb — unsafe XML parsing.
        if method == "parse" || method == "fromstring" {
            if let Expr::Name(obj) = attr.value.as_ref() {
                let obj_name = obj.id.as_str();
                let source_has_defusedxml = file.source.contains("defusedxml");
                if !source_has_defusedxml
                    && (obj_name.contains("xml")
                        || obj_name.contains("etree")
                        || obj_name.contains("minidom")
                        || obj_name.contains("sax")
                        || obj_name == "ElementTree"
                        || obj_name == "ET")
                {
                    bag.push(
                        Diagnostic::new(
                            "SEC006",
                            "xml-bomb",
                            format!("`{obj_name}.{method}()` is vulnerable to XML External Entity (XXE) attacks and XML bombs"),
                            file.location_from_range(&attr.range),
                            Severity::Warning,
                            Category::Security,
                        )
                        .with_suggestion("Use `defusedxml` library instead, or disable external entity processing."),
                    );
                }
            }
        }

        // SEC002: .format() called on a string containing SQL keywords.
        if method == "format" {
            if let Expr::Constant(c) = attr.value.as_ref() {
                if let ignyt_ast::Constant::Str(s) = &c.value {
                    if contains_sql_keyword(s) {
                        bag.push(
                            Diagnostic::new(
                                "SEC002",
                                "sql-injection",
                                "`.format()` used to build a SQL query — potential SQL injection",
                                file.location_from_range(&attr.range),
                                Severity::Critical,
                                Category::Security,
                            )
                            .with_suggestion(
                                "Use parameterized queries (e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`).",
                            ),
                        );
                    }
                }
            }
        }
    }
}

/// SEC001: Hardcoded passwords in assignments.
fn check_hardcoded_password(
    assign: &ignyt_ast::StmtAssign,
    file: &SourceFile,
    bag: &mut DiagnosticBag,
) {
    use ignyt_ast::Expr;

    const SENSITIVE_NAMES: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "auth_token",
        "secret_key",
        "private_key",
    ];

    // Check if the value is a string literal.
    let is_string_literal = matches!(assign.value.as_ref(), Expr::Constant(c)
        if c.value.is_str());

    if !is_string_literal {
        return;
    }

    for target in &assign.targets {
        if let Expr::Name(name) = target {
            let var_name = name.id.as_str().to_lowercase();
            if SENSITIVE_NAMES.iter().any(|s| var_name.contains(s)) {
                bag.push(
                    Diagnostic::new(
                        "SEC001",
                        "hardcoded-password",
                        format!("Hardcoded credential in `{}`", name.id.as_str()),
                        file.location_from_range(&name.range),
                        Severity::Critical,
                        Category::Security,
                    )
                    .with_suggestion("Use environment variables or a secrets manager."),
                );
            }
        }
    }
}

/// SEC007: assert used in non-test code.
fn check_assert_usage(stmt: &ignyt_ast::Stmt, file: &SourceFile, bag: &mut DiagnosticBag) {
    use ignyt_ast::Stmt;

    if let Stmt::Assert(assert_stmt) = stmt {
        // Skip test files.
        let path_str = file.path.to_string_lossy();
        if path_str.contains("test") || path_str.contains("conftest") {
            return;
        }

        bag.push(
            Diagnostic::new(
                "SEC007",
                "assert-used",
                "`assert` statements are removed when Python runs with `-O` (optimized mode)",
                file.location_from_range(&assert_stmt.range),
                Severity::Warning,
                Category::Security,
            )
            .with_suggestion("Use explicit `if not condition: raise` for runtime checks."),
        );
    }
}

/// SEC003: Detect `subprocess.call(..., shell=True)`.
fn check_shell_injection(file: &SourceFile, bag: &mut DiagnosticBag) {
    let source = &file.source;
    for (line_num, line) in source.lines().enumerate() {
        if line.contains("shell=True") && line.contains("subprocess") {
            let location = Location::new(&file.path, line_num + 1, 1);
            bag.push(
                Diagnostic::new(
                    "SEC003",
                    "shell-injection",
                    "`subprocess` call with `shell=True` is vulnerable to shell injection",
                    location,
                    Severity::Critical,
                    Category::Security,
                )
                .with_suggestion("Use `shell=False` (default) and pass args as a list."),
            );
        }
    }
}

/// SEC006: Line-based heuristic for `xml.etree.ElementTree` and similar imports
/// without `defusedxml`.
fn check_xml_import(file: &SourceFile, bag: &mut DiagnosticBag) {
    let source = &file.source;
    let has_defusedxml = source.lines().any(|line| line.contains("defusedxml"));

    if has_defusedxml {
        return;
    }

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if (trimmed.starts_with("import ") || trimmed.starts_with("from "))
            && (trimmed.contains("xml.etree.ElementTree")
                || trimmed.contains("xml.dom.minidom")
                || trimmed.contains("xml.sax")
                || trimmed.contains("lxml.etree"))
        {
            let location = Location::new(&file.path, line_num + 1, 1);
            bag.push(
                Diagnostic::new(
                    "SEC006",
                    "xml-bomb",
                    "Import of unsafe XML parser — vulnerable to XXE attacks and XML bombs",
                    location,
                    Severity::Warning,
                    Category::Security,
                )
                .with_suggestion(
                    "Use `defusedxml` library instead, or disable external entity processing.",
                ),
            );
        }
    }
}

/// SEC010: DEBUG = True in non-test files.
fn check_debug_enabled(file: &SourceFile, bag: &mut DiagnosticBag) {
    let path_str = file.path.to_string_lossy();
    if path_str.contains("test") {
        return;
    }

    use ignyt_ast::{Expr, Stmt};
    for stmt in file.body() {
        if let Stmt::Assign(assign) = stmt {
            for target in &assign.targets {
                if let Expr::Name(name) = target {
                    if name.id.as_str() == "DEBUG" {
                        if let Expr::Constant(c) = assign.value.as_ref() {
                            if c.value.clone().is_true() {
                                bag.push(
                                    Diagnostic::new(
                                        "SEC010",
                                        "debug-enabled",
                                        "`DEBUG = True` should not be used in production code",
                                        file.location_from_range(&name.range),
                                        Severity::Warning,
                                        Category::Security,
                                    )
                                    .with_suggestion(
                                        "Set `DEBUG = False` or use environment variables.",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SEC002 helpers
// ---------------------------------------------------------------------------

/// Return true if the string contains a SQL keyword that suggests query building.
fn contains_sql_keyword(s: &str) -> bool {
    const SQL_KEYWORDS: &[&str] = &[
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "UNION",
    ];
    let upper = s.to_uppercase();
    SQL_KEYWORDS.iter().any(|kw| upper.contains(kw))
}

/// SEC002: f-string (`JoinedStr`) used to build a SQL query.
fn check_sql_injection_fstring(
    fstr: &ignyt_ast::ExprJoinedStr,
    file: &SourceFile,
    bag: &mut DiagnosticBag,
) {
    use ignyt_ast::{Constant, Expr};

    // Collect all literal string pieces inside the f-string.
    let literal_parts: String = fstr
        .values
        .iter()
        .filter_map(|v| {
            if let Expr::Constant(c) = v {
                if let Constant::Str(s) = &c.value {
                    return Some(s.as_str());
                }
            }
            None
        })
        .collect();

    // Only flag if the f-string actually has interpolated expressions (i.e. it
    // is a real f-string, not just a plain string written with f-prefix).
    let has_interpolation = fstr
        .values
        .iter()
        .any(|v| matches!(v, Expr::FormattedValue(_)));

    if has_interpolation && contains_sql_keyword(&literal_parts) {
        bag.push(
            Diagnostic::new(
                "SEC002",
                "sql-injection",
                "f-string used to build a SQL query — potential SQL injection",
                file.location_from_range(&fstr.range),
                Severity::Critical,
                Category::Security,
            )
            .with_suggestion(
                "Use parameterized queries (e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`).",
            ),
        );
    }
}

/// SEC002: string concatenation (`+`) used to build a SQL query.
fn check_sql_injection_binop(
    op: &ignyt_ast::ExprBinOp,
    file: &SourceFile,
    bag: &mut DiagnosticBag,
) {
    use ignyt_ast::{Constant, Expr, Operator};

    if op.op != Operator::Add {
        return;
    }

    let string_side_has_sql = |expr: &Expr| -> bool {
        if let Expr::Constant(c) = expr {
            if let Constant::Str(s) = &c.value {
                return contains_sql_keyword(s);
            }
        }
        false
    };

    let left_is_sql = string_side_has_sql(&op.left);
    let right_is_sql = string_side_has_sql(&op.right);

    // Flag only when one side is a SQL-keyword string and the other side is a
    // variable (Name), indicating dynamic concatenation.
    let left_is_var = matches!(op.left.as_ref(), Expr::Name(_));
    let right_is_var = matches!(op.right.as_ref(), Expr::Name(_));

    if (left_is_sql && right_is_var) || (right_is_sql && left_is_var) {
        bag.push(
            Diagnostic::new(
                "SEC002",
                "sql-injection",
                "String concatenation used to build a SQL query — potential SQL injection",
                file.location_from_range(&op.range),
                Severity::Critical,
                Category::Security,
            )
            .with_suggestion(
                "Use parameterized queries (e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`).",
            ),
        );
    }
}

/// SEC002: `.format()` called on a SQL-keyword string — checked at the assign level
/// so that patterns like `query = "SELECT ...".format(...)` are caught in the
/// assignment value expression tree (the call is visited by `visit_expr` via the
/// `Expr::Call` arm, but we also need to handle it when the assignment value is
/// the call itself).  The actual detection lives in `check_dangerous_call` under
/// the `method == "format"` branch, so this function is a no-op placeholder kept
/// for clarity.
fn check_sql_injection_format_assign(
    _assign: &ignyt_ast::StmtAssign,
    _file: &SourceFile,
    _bag: &mut DiagnosticBag,
) {
    // Detection is handled in `check_dangerous_call` via the attribute-call
    // path (method == "format").  visit_expr already recurses into the
    // assignment value so nothing extra is needed here.
}

// ---------------------------------------------------------------------------
// SEC009 helper
// ---------------------------------------------------------------------------

/// SEC009: Hardcoded tokens / API keys in variable assignments.
fn check_hardcoded_token(
    assign: &ignyt_ast::StmtAssign,
    file: &SourceFile,
    bag: &mut DiagnosticBag,
) {
    use ignyt_ast::{Constant, Expr};

    const TOKEN_PATTERNS: &[&str] = &[
        "_token",
        "_key",
        "_secret",
        "_password",
        "_credential",
        "aws_",
        "github_",
        "slack_",
    ];

    const TOKEN_PREFIXES: &[&str] = &["sk-", "pk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA"];

    // Value must be a string literal.
    let string_value = if let Expr::Constant(c) = assign.value.as_ref() {
        if let Constant::Str(s) = &c.value {
            s.clone()
        } else {
            return;
        }
    } else {
        return;
    };

    // Must be long enough to be a token (>= 16 chars).
    if string_value.len() < 16 {
        return;
    }

    // Must look like a token: either starts with a known prefix, or is
    // alphanumeric (hex / base64-like).
    let looks_like_token = TOKEN_PREFIXES.iter().any(|p| string_value.starts_with(p))
        || string_value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '/');

    if !looks_like_token {
        return;
    }

    for target in &assign.targets {
        if let Expr::Name(name) = target {
            let var_name = name.id.as_str().to_lowercase();
            if TOKEN_PATTERNS.iter().any(|p| var_name.contains(p)) {
                bag.push(
                    Diagnostic::new(
                        "SEC009",
                        "hardcoded-token",
                        format!("Hardcoded token or API key in `{}`", name.id.as_str()),
                        file.location_from_range(&name.range),
                        Severity::Critical,
                        Category::Security,
                    )
                    .with_suggestion(
                        "Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
                    ),
                );
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

    fn parse_with_path(path: &str, source: &str) -> SourceFile {
        SourceFile::parse_source(PathBuf::from(path), source.to_string()).unwrap()
    }

    // SEC011: eval/exec
    #[test]
    fn test_eval_detected() {
        let file = parse("eval(user_input)\n");
        let bag = check_security(&file).unwrap();
        assert_eq!(bag.len(), 1);
        assert_eq!(bag.diagnostics()[0].code, "SEC011");
    }

    #[test]
    fn test_exec_detected() {
        let file = parse("exec(code_str)\n");
        let bag = check_security(&file).unwrap();
        assert_eq!(bag.len(), 1);
        assert_eq!(bag.diagnostics()[0].code, "SEC011");
    }

    #[test]
    fn test_eval_inside_assignment() {
        let file = parse("result = eval(data)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC011"));
    }

    #[test]
    fn test_eval_inside_function() {
        let file = parse("def foo():\n    x = eval('1+1')\n    return x\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC011"));
    }

    // SEC001: hardcoded passwords
    #[test]
    fn test_hardcoded_password() {
        let file = parse("password = 'hunter2'\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC001"));
    }

    #[test]
    fn test_hardcoded_api_key() {
        let file = parse("API_KEY = 'sk-1234567890abcdef'\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC001"));
    }

    #[test]
    fn test_non_literal_password_ok() {
        let file = parse("password = os.environ['PASSWORD']\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC001"));
    }

    // SEC003: shell injection
    #[test]
    fn test_shell_injection_detected() {
        let file = parse("import subprocess\nsubprocess.call('ls', shell=True)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC003"));
    }

    #[test]
    fn test_subprocess_without_shell_true_ok() {
        let file = parse("import subprocess\nsubprocess.call(['ls'])\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC003"));
    }

    // SEC005: yaml.load
    #[test]
    fn test_yaml_unsafe_load() {
        let file = parse("import yaml\ndata = yaml.load(content)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC005"));
    }

    #[test]
    fn test_yaml_safe_load_ok() {
        let file = parse("import yaml\ndata = yaml.load(content, Loader=yaml.SafeLoader)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC005"));
    }

    // SEC004: pickle
    #[test]
    fn test_pickle_loads() {
        let file = parse("import pickle\nobj = pickle.loads(data)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC004"));
    }

    // SEC007: assert in non-test code
    #[test]
    fn test_assert_in_production_code() {
        let file = parse_with_path("src/app.py", "assert x > 0\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC007"));
    }

    #[test]
    fn test_assert_in_test_file_ok() {
        let file = parse_with_path("tests/test_app.py", "assert x > 0\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC007"));
    }

    // SEC008: weak crypto
    #[test]
    fn test_weak_crypto_md5() {
        let file = parse("import hashlib\nh = hashlib.md5(data)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC008"));
    }

    #[test]
    fn test_strong_crypto_ok() {
        let file = parse("import hashlib\nh = hashlib.sha256(data)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC008"));
    }

    // SEC010: DEBUG = True
    #[test]
    fn test_debug_enabled() {
        let file = parse_with_path("src/settings.py", "DEBUG = True\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC010"));
    }

    #[test]
    fn test_debug_false_ok() {
        let file = parse_with_path("src/settings.py", "DEBUG = False\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC010"));
    }

    // Clean code
    #[test]
    fn test_safe_code_no_findings() {
        let file = parse("x = 1 + 2\nprint(x)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.is_empty());
    }

    // SEC002: SQL injection
    #[test]
    fn test_sql_injection_fstring_detected() {
        let file = parse("query = f\"SELECT * FROM users WHERE id = {user_id}\"\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC002"));
    }

    #[test]
    fn test_fstring_without_sql_ok() {
        let file = parse("msg = f\"Hello, {name}!\"\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC002"));
    }

    #[test]
    fn test_sql_injection_string_concat_detected() {
        let file = parse("query = \"SELECT * FROM users WHERE name = \" + user_input\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC002"));
    }

    #[test]
    fn test_sql_injection_format_detected() {
        let file = parse("query = \"SELECT * FROM users WHERE id = {}\".format(user_id)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC002"));
    }

    #[test]
    fn test_format_without_sql_ok() {
        let file = parse("msg = \"Hello, {}!\".format(name)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC002"));
    }

    // SEC009: hardcoded tokens
    #[test]
    fn test_hardcoded_github_token_detected() {
        let file = parse("github_token = \"ghp_abc123xyz456def789ghi012jkl345\"\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC009"));
    }

    #[test]
    fn test_short_token_not_flagged() {
        let file = parse("github_token = \"short\"\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC009"));
    }

    #[test]
    fn test_hardcoded_aws_secret_key_detected() {
        let file = parse("aws_secret_key = \"AKIAiosfodnn7EXAMPLE1234\"\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC009"));
    }

    // SEC012: path traversal
    #[test]
    fn test_open_with_variable_detected() {
        let file = parse("f = open(user_input)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC012"));
    }

    #[test]
    fn test_open_with_literal_ok() {
        let file = parse("f = open(\"config.json\")\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC012"));
    }

    #[test]
    fn test_os_path_join_with_variable_detected() {
        let file = parse("import os\npath = os.path.join(\"/base\", user_dir)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC012"));
    }

    // SEC006: XML bomb / XXE
    #[test]
    fn test_xml_etree_parse_detected() {
        let file = parse("import xml.etree.ElementTree as ET\ntree = ET.parse('data.xml')\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC006"));
    }

    #[test]
    fn test_xml_elementtree_fromstring_detected() {
        let file = parse("from xml.etree import ElementTree\ndoc = ElementTree.fromstring(data)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().any(|d| d.code == "SEC006"));
    }

    #[test]
    fn test_defusedxml_parse_ok() {
        let file = parse("import defusedxml.ElementTree as ET\ntree = ET.parse('data.xml')\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC006"));
    }

    #[test]
    fn test_unrelated_parse_call_ok() {
        let file = parse("import json\ndata = json.parse(content)\n");
        let bag = check_security(&file).unwrap();
        assert!(bag.diagnostics().iter().all(|d| d.code != "SEC006"));
    }
}
