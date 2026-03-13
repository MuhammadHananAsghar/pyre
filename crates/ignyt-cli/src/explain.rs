//! Rule documentation for `ignyt explain <CODE>`.
//!
//! Provides detailed descriptions, examples, and fix guidance for every
//! diagnostic rule Ignyt can emit.

use owo_colors::OwoColorize;

struct RuleDoc {
    code: &'static str,
    name: &'static str,
    category: &'static str,
    severity: &'static str,
    summary: &'static str,
    detail: &'static str,
    example_bad: &'static str,
    example_good: &'static str,
    fixable: bool,
}

static RULES: &[RuleDoc] = &[
    // ── Security ─────────────────────────────────────────────────────────
    RuleDoc {
        code: "SEC001",
        name: "hardcoded-password",
        category: "Security",
        severity: "Critical",
        summary: "Hardcoded credential detected in source code.",
        detail: "Variables whose name contains `password`, `secret`, `api_key`, `token`, \
                 or similar patterns should never be assigned string literals. Credentials \
                 must come from environment variables or a secrets manager.",
        example_bad: "password = \"hunter2\"",
        example_good: "password = os.environ[\"PASSWORD\"]",
        fixable: false,
    },
    RuleDoc {
        code: "SEC002",
        name: "sql-injection",
        category: "Security",
        severity: "Critical",
        summary: "Dynamic SQL query built via string interpolation.",
        detail: "Building SQL queries with f-strings, `.format()`, or string concatenation \
                 allows an attacker to inject arbitrary SQL. Always use parameterized \
                 queries provided by your database driver.",
        example_bad: "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
        example_good: "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
        fixable: false,
    },
    RuleDoc {
        code: "SEC003",
        name: "shell-injection",
        category: "Security",
        severity: "Critical",
        summary: "`subprocess` called with `shell=True`.",
        detail: "Passing `shell=True` to `subprocess.call/run/Popen` interprets the \
                 command through the shell, enabling injection if any argument comes from \
                 user input. Pass args as a list with `shell=False` (the default).",
        example_bad: "subprocess.call(f\"deploy.sh {target}\", shell=True)",
        example_good: "subprocess.run([\"deploy.sh\", target], shell=False)",
        fixable: false,
    },
    RuleDoc {
        code: "SEC004",
        name: "pickle-usage",
        category: "Security",
        severity: "Critical",
        summary: "`pickle.loads/load` can execute arbitrary code.",
        detail: "Python's `pickle` module can execute arbitrary code during deserialization. \
                 Never use pickle with untrusted data. Prefer `json` or `msgpack`.",
        example_bad: "obj = pickle.loads(untrusted_data)",
        example_good: "obj = json.loads(untrusted_data)",
        fixable: false,
    },
    RuleDoc {
        code: "SEC005",
        name: "yaml-unsafe-load",
        category: "Security",
        severity: "Critical",
        summary: "`yaml.load()` without SafeLoader allows code execution.",
        detail: "The default YAML loader can instantiate arbitrary Python objects. Use \
                 `yaml.safe_load()` or explicitly pass `Loader=yaml.SafeLoader`.",
        example_bad: "data = yaml.load(content)",
        example_good: "data = yaml.safe_load(content)",
        fixable: true,
    },
    RuleDoc {
        code: "SEC006",
        name: "xml-bomb",
        category: "Security",
        severity: "Warning",
        summary: "XML parsing without defusedxml may be vulnerable to XXE attacks.",
        detail: "Python's standard `xml` module does not protect against XML External \
                 Entity (XXE) attacks or billion-laughs denial of service. Use the \
                 `defusedxml` library instead.",
        example_bad: "tree = ET.parse(untrusted_file)",
        example_good: "import defusedxml.ElementTree as ET\ntree = ET.parse(untrusted_file)",
        fixable: false,
    },
    RuleDoc {
        code: "SEC007",
        name: "assert-used",
        category: "Security",
        severity: "Warning",
        summary: "`assert` removed under `-O` (optimized mode).",
        detail: "Python strips `assert` statements when run with `-O` or `-OO`. Never \
                 use `assert` for security checks or input validation in production code.",
        example_bad: "assert user.is_admin, \"unauthorized\"",
        example_good: "if not user.is_admin:\n    raise PermissionError(\"unauthorized\")",
        fixable: false,
    },
    RuleDoc {
        code: "SEC008",
        name: "weak-crypto",
        category: "Security",
        severity: "Warning",
        summary: "Weak hash algorithm (MD5/SHA1).",
        detail: "MD5 and SHA1 are cryptographically broken and should not be used for \
                 security-sensitive hashing (passwords, tokens, signatures). Use SHA-256 \
                 or bcrypt/argon2 for password hashing.",
        example_bad: "digest = hashlib.md5(data).hexdigest()",
        example_good: "digest = hashlib.sha256(data).hexdigest()",
        fixable: false,
    },
    RuleDoc {
        code: "SEC009",
        name: "hardcoded-token",
        category: "Security",
        severity: "Critical",
        summary: "Hardcoded API token or key detected.",
        detail: "Long string literals assigned to variables containing `_token`, `_key`, \
                 `_secret`, or starting with known prefixes like `ghp_`, `sk-`, `AKIA` \
                 are likely hardcoded credentials. Store them in environment variables.",
        example_bad: "github_token = \"ghp_abc123...\"",
        example_good: "github_token = os.environ[\"GITHUB_TOKEN\"]",
        fixable: false,
    },
    RuleDoc {
        code: "SEC010",
        name: "debug-enabled",
        category: "Security",
        severity: "Warning",
        summary: "`DEBUG = True` in non-test code.",
        detail: "Leaving debug mode enabled in production exposes stack traces, internal \
                 state, and potentially sensitive data. Set `DEBUG = False` or read from \
                 an environment variable.",
        example_bad: "DEBUG = True",
        example_good: "DEBUG = os.environ.get(\"DEBUG\", \"false\").lower() == \"true\"",
        fixable: false,
    },
    RuleDoc {
        code: "SEC011",
        name: "eval-usage",
        category: "Security",
        severity: "Critical",
        summary: "`eval()`/`exec()` can execute arbitrary code.",
        detail: "`eval()` and `exec()` execute arbitrary Python code. If the input comes \
                 from an untrusted source, this is a remote code execution vulnerability. \
                 Use `ast.literal_eval()` for safe parsing of literals.",
        example_bad: "result = eval(user_input)",
        example_good: "result = ast.literal_eval(user_input)",
        fixable: false,
    },
    RuleDoc {
        code: "SEC012",
        name: "path-traversal",
        category: "Security",
        severity: "Warning",
        summary: "File path from variable input — potential path traversal.",
        detail: "`open()` or `os.path.join()` called with a variable path argument may \
                 allow an attacker to read or write arbitrary files using `../` sequences. \
                 Validate paths against an allowed base directory.",
        example_bad: "data = open(user_path).read()",
        example_good: "safe = os.path.realpath(user_path)\nassert safe.startswith(BASE_DIR)",
        fixable: false,
    },
    // ── Types ────────────────────────────────────────────────────────────
    RuleDoc {
        code: "TYPE001",
        name: "missing-return",
        category: "Type",
        severity: "Error",
        summary: "Function has return annotation but no `return` statement.",
        detail: "A function annotated with a non-None return type should always return a \
                 value. A missing return causes `None` to be returned implicitly, violating \
                 the declared type.",
        example_bad: "def get_count() -> int:\n    x = compute()",
        example_good: "def get_count() -> int:\n    return compute()",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE002",
        name: "incompatible-default",
        category: "Type",
        severity: "Error",
        summary: "Default argument type conflicts with annotation.",
        detail: "When a parameter has both a type annotation and a default value, the \
                 default should match the declared type. For example, `x: int = \"hello\"` \
                 is always wrong.",
        example_bad: "def greet(name: str = 42) -> str: ...",
        example_good: "def greet(name: str = \"world\") -> str: ...",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE003",
        name: "missing-annotation",
        category: "Type",
        severity: "Warning",
        summary: "Public function missing return type annotation.",
        detail: "Public functions should declare their return type for documentation and \
                 type safety. Add `-> ReturnType` to the function signature.",
        example_bad: "def process(data):\n    return data",
        example_good: "def process(data: bytes) -> bytes:\n    return data",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE004",
        name: "redundant-cast",
        category: "Type",
        severity: "Hint",
        summary: "Redundant type cast on already-typed parameter.",
        detail: "Casting a parameter to its own annotated type (e.g., `int(x)` where x \
                 is `int`) is a no-op and adds noise. Remove the unnecessary cast.",
        example_bad: "def foo(x: int) -> int:\n    return int(x)",
        example_good: "def foo(x: int) -> int:\n    return x",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE005",
        name: "mutable-default",
        category: "Type",
        severity: "Warning",
        summary: "Mutable default argument (list, dict, or set).",
        detail: "Mutable default arguments are shared across all calls and can cause \
                 unexpected behavior. Use `None` as the default and create a new instance \
                 inside the function.",
        example_bad: "def append(items: list = []):\n    items.append(1)",
        example_good: "def append(items: list | None = None):\n    if items is None:\n        items = []",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE006",
        name: "redundant-isinstance",
        category: "Type",
        severity: "Hint",
        summary: "Redundant `isinstance()` check on already-typed parameter.",
        detail: "Checking `isinstance(x, int)` when `x` is annotated as `int` is always \
                 true and adds unnecessary complexity.",
        example_bad: "def foo(x: int) -> int:\n    if isinstance(x, int): ...",
        example_good: "def foo(x: int) -> int:\n    return x + 1",
        fixable: false,
    },
    RuleDoc {
        code: "TYPE007",
        name: "none-not-checked",
        category: "Type",
        severity: "Warning",
        summary: "`Optional` parameter used without a `None` check.",
        detail: "Accessing attributes on an `Optional[X]` value without first checking \
                 for `None` will raise `AttributeError` at runtime when the value is None.",
        example_bad: "def greet(name: Optional[str]) -> str:\n    return name.upper()",
        example_good: "def greet(name: Optional[str]) -> str:\n    if name is None:\n        return \"anon\"\n    return name.upper()",
        fixable: false,
    },
    // ── Dead Code ────────────────────────────────────────────────────────
    RuleDoc {
        code: "DEAD001",
        name: "unused-function",
        category: "Dead Code",
        severity: "Warning",
        summary: "Private function defined but never called.",
        detail: "A function starting with `_` (single underscore) that isn't referenced \
                 anywhere in the file is likely dead code. Remove it or make it public \
                 if it's used elsewhere.",
        example_bad: "def _old_helper():\n    return 42",
        example_good: "# remove unused function, or use it",
        fixable: false,
    },
    RuleDoc {
        code: "DEAD002",
        name: "unused-class",
        category: "Dead Code",
        severity: "Warning",
        summary: "Private class defined but never referenced.",
        detail: "A class starting with `_` that isn't instantiated or referenced in the \
                 file is likely dead code.",
        example_bad: "class _OldHelper:\n    pass",
        example_good: "# remove unused class, or use it",
        fixable: false,
    },
    RuleDoc {
        code: "DEAD003",
        name: "unused-variable",
        category: "Dead Code",
        severity: "Warning",
        summary: "Variable assigned but never used.",
        detail: "A variable that is assigned but never referenced afterward wastes memory \
                 and makes code harder to read. Remove the assignment or use `_` as the \
                 variable name if the value is intentionally discarded.",
        example_bad: "def foo():\n    unused = compute()\n    return 0",
        example_good: "def foo():\n    _ = compute()  # intentionally discarded\n    return 0",
        fixable: false,
    },
    RuleDoc {
        code: "DEAD004",
        name: "unused-import",
        category: "Dead Code",
        severity: "Warning",
        summary: "Import never used.",
        detail: "An imported module or name that is never referenced in the file wastes \
                 startup time and clutters the namespace. Remove it.",
        example_bad: "import json  # never used",
        example_good: "# remove the import",
        fixable: true,
    },
    RuleDoc {
        code: "DEAD005",
        name: "unused-argument",
        category: "Dead Code",
        severity: "Hint",
        summary: "Function argument never used in body.",
        detail: "A parameter that is never referenced in the function body may indicate \
                 a bug or an outdated API. If the argument is required by an interface, \
                 prefix it with `_` to signal intentional non-use.",
        example_bad: "def process(data, options):\n    return data",
        example_good: "def process(data, _options):\n    return data",
        fixable: false,
    },
    RuleDoc {
        code: "DEAD006",
        name: "unreachable-code",
        category: "Dead Code",
        severity: "Warning",
        summary: "Code after `return`/`raise`/`break`/`continue` is unreachable.",
        detail: "Statements after a terminator (`return`, `raise`, `break`, `continue`) \
                 can never execute. Remove them to avoid confusion.",
        example_bad: "def foo():\n    return 1\n    print(\"never runs\")",
        example_good: "def foo():\n    return 1",
        fixable: false,
    },
    // ── Complexity ───────────────────────────────────────────────────────
    RuleDoc {
        code: "CMPLX001",
        name: "high-cyclomatic-complexity",
        category: "Complexity",
        severity: "Warning",
        summary: "Function has too many decision branches.",
        detail: "Cyclomatic complexity counts the number of independent paths through a \
                 function. High complexity makes code hard to test and maintain. Extract \
                 helper functions or use early returns to simplify.",
        example_bad: "def process(x):\n    if a: ...\n    elif b: ...\n    elif c: ...\n    # many more branches",
        example_good: "Split into smaller functions with single responsibilities.",
        fixable: false,
    },
    RuleDoc {
        code: "CMPLX003",
        name: "too-many-arguments",
        category: "Complexity",
        severity: "Warning",
        summary: "Function has too many parameters.",
        detail: "Functions with many parameters are hard to call correctly and often \
                 indicate that related parameters should be grouped into a data class \
                 or dictionary.",
        example_bad: "def create(a, b, c, d, e, f, g): ...",
        example_good: "def create(config: Config): ...",
        fixable: false,
    },
    // ── Format ───────────────────────────────────────────────────────────
    RuleDoc {
        code: "FMT001",
        name: "unsorted-imports",
        category: "Format",
        severity: "Hint",
        summary: "Import statements are not sorted alphabetically.",
        detail: "Keeping imports sorted makes them easier to scan and reduces merge \
                 conflicts. Ignyt sorts imports alphabetically by module name.",
        example_bad: "import sys\nimport os\nimport ast",
        example_good: "import ast\nimport os\nimport sys",
        fixable: true,
    },
    RuleDoc {
        code: "FMT002",
        name: "line-too-long",
        category: "Format",
        severity: "Hint",
        summary: "Line exceeds configured maximum length.",
        detail: "Long lines reduce readability and cause horizontal scrolling. The default \
                 limit is 88 characters (configurable in `ignyt.toml`).",
        example_bad: "x = some_very_long_function_name(with_many_arguments, that_makes_line_exceed_the_limit)",
        example_good: "x = some_very_long_function_name(\n    with_many_arguments,\n    that_makes_line_shorter,\n)",
        fixable: false,
    },
];

/// Print detailed documentation for a single rule.
pub fn explain_rule(code: &str) {
    let code_upper = code.to_uppercase();
    let doc = RULES.iter().find(|r| r.code == code_upper);

    match doc {
        Some(rule) => {
            println!();
            println!(
                "  {} {} ({})",
                rule.code.bold().cyan(),
                rule.name.bold(),
                rule.category.dimmed()
            );
            println!("  {} {}", "Severity:".dimmed(), rule.severity);
            if rule.fixable {
                println!("  {} auto-fixable with `ignyt fix`", "✓".green());
            }
            println!();
            println!("  {}", rule.summary);
            println!();
            println!("  {}", rule.detail);
            println!();
            println!("  {}", "Bad:".red().bold());
            for line in rule.example_bad.lines() {
                println!("    {}", line.red());
            }
            println!();
            println!("  {}", "Good:".green().bold());
            for line in rule.example_good.lines() {
                println!("    {}", line.green());
            }
            println!();
        }
        None => {
            println!();
            println!("  {} Unknown rule code: {}", "✗".red().bold(), code.bold());
            println!();
            println!("  Available rules:");
            println!();
            for rule in RULES {
                println!("    {:<10} {}", rule.code.cyan(), rule.summary);
            }
            println!();
        }
    }
}
