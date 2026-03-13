# Ignyt - The Fastest Python Code Quality Engine

> **One binary. Zero config. Replaces mypy, flake8, bandit, vulture, radon, black, and isort.**

Ignyt is a standalone, self-contained Python code quality engine written in Rust. It performs type checking, security scanning, dead code detection, complexity analysis, formatting checks, and auto-fixing — all in a single binary that runs 10-100x faster than the tools it replaces.

## Features

- **Type Checking** — Missing annotations, incompatible defaults, missing returns, Optional safety, mutable defaults, redundant casts/isinstance
- **Security Scanning** — Hardcoded credentials, SQL injection, shell injection, eval/exec, pickle, unsafe YAML, weak crypto, XML bombs, path traversal
- **Dead Code Detection** — Unused imports, functions, classes, variables, arguments, unreachable code
- **Complexity Analysis** — Cyclomatic complexity, cognitive complexity, argument count, nesting depth, line count
- **Format Checking** — Import ordering, line length
- **Auto-Fix** — Removes unused imports, fixes `yaml.load` → `yaml.safe_load`, sorts imports
- **Watch Mode** — Re-runs checks on file changes
- **Rule Documentation** — Built-in `ignyt explain <CODE>` for detailed rule descriptions

## Quick Start

```bash
# Install via pip
pip install ignyt

# Run all checks on your project
ignyt check src/

# Run specific engines
ignyt types src/
ignyt security src/
ignyt dead src/
ignyt complexity src/

# Auto-fix safe issues
ignyt fix src/

# Get help on a specific rule
ignyt explain SEC001

# Watch mode
ignyt watch src/

# JSON output for CI/CD integration
ignyt check --format json src/
```

## Diagnostic Rules

### Security (SEC001-SEC012)
| Code | Name | Description |
|------|------|-------------|
| SEC001 | hardcoded-password | Hardcoded credentials in source code |
| SEC002 | sql-injection | SQL query built via string interpolation |
| SEC003 | shell-injection | `subprocess` with `shell=True` |
| SEC004 | pickle-usage | `pickle.loads/load` can execute arbitrary code |
| SEC005 | yaml-unsafe-load | `yaml.load()` without SafeLoader |
| SEC006 | xml-bomb | XML parsing vulnerable to XXE attacks |
| SEC007 | assert-used | `assert` removed under `-O` mode |
| SEC008 | weak-crypto | MD5/SHA1 hash algorithms |
| SEC009 | hardcoded-token | Hardcoded API tokens/keys |
| SEC010 | debug-enabled | `DEBUG = True` in production |
| SEC011 | eval-usage | `eval()`/`exec()` usage |
| SEC012 | path-traversal | File path from unsanitized input |

### Type Checking (TYPE001-TYPE007)
| Code | Name | Description |
|------|------|-------------|
| TYPE001 | missing-return | Function with return annotation but no return |
| TYPE002 | incompatible-default | Default value type conflicts with annotation |
| TYPE003 | missing-annotation | Public function missing return type annotation |
| TYPE004 | redundant-cast | Redundant type cast on already-typed parameter |
| TYPE005 | mutable-default | Mutable default argument (list, dict, set) |
| TYPE006 | redundant-isinstance | Redundant isinstance check on typed parameter |
| TYPE007 | none-not-checked | Optional parameter used without None check |

### Dead Code (DEAD001-DEAD006)
| Code | Name | Description |
|------|------|-------------|
| DEAD001 | unused-function | Private function never called |
| DEAD002 | unused-class | Private class never referenced |
| DEAD003 | unused-variable | Variable assigned but never used |
| DEAD004 | unused-import | Import never used |
| DEAD005 | unused-argument | Function argument never used |
| DEAD006 | unreachable-code | Code after return/raise/break/continue |

### Complexity (CMPLX001-CMPLX007)
| Code | Name | Description |
|------|------|-------------|
| CMPLX001 | high-cyclomatic | Too many decision branches |
| CMPLX003 | too-many-arguments | Too many function parameters |

### Format (FMT001-FMT002)
| Code | Name | Description |
|------|------|-------------|
| FMT001 | unsorted-imports | Imports not sorted alphabetically |
| FMT002 | line-too-long | Line exceeds max length |

## Configuration

Create an `ignyt.toml` in your project root:

```toml
[ignyt]
python = "3.12"
src = ["src/", "tests/"]
exclude = ["migrations/", "*_pb2.py"]

[ignyt.fmt]
line-length = 120
quote-style = "single"

[ignyt.types]
strict = true
check-untyped-defs = true

[ignyt.security]
level = "high"
ignore = ["SEC007"]

[ignyt.complexity]
max-cyclomatic = 15
max-args = 8

[ignyt.rules]
error = ["SEC001", "TYPE001"]
warn = ["DEAD001"]
skip = ["FMT002"]
```

## Architecture

Ignyt is a Rust workspace with 10 crates:

```
crates/
  ignyt-cli/          # CLI entry point, command dispatch, output rendering
  ignyt-ast/          # Python AST parsing (via rustpython-parser)
  ignyt-types/        # Type inference and checking engine
  ignyt-security/     # Security pattern matching (bandit replacement)
  ignyt-dead/         # Dead code and unused symbol detection
  ignyt-complexity/   # Cyclomatic and cognitive complexity analysis
  ignyt-fmt/          # Import sorting and format checking
  ignyt-diagnostics/  # Shared diagnostic types and error handling
  ignyt-config/       # TOML configuration parsing
  ignyt-fix/          # Auto-fix engine
```

## Performance

Ignyt uses:
- **Rayon** for parallel file analysis across all CPU cores
- **rustpython-parser** for zero-copy Python AST parsing
- **LTO + single codegen unit** in release builds for maximum optimization

## License

MIT
