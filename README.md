<p align="center">
  <h1 align="center">Ignyt</h1>
  <p align="center"><strong>The fastest Python code quality engine in the world.</strong></p>
  <p align="center">
    <a href="https://pypi.org/project/ignyt/"><img src="https://img.shields.io/pypi/v/ignyt?color=blue&label=PyPI" alt="PyPI"></a>
    <a href="https://pypi.org/project/ignyt/"><img src="https://img.shields.io/pypi/pyversions/ignyt" alt="Python"></a>
    <a href="https://github.com/MuhammadHananAsghar/ignyt/actions"><img src="https://github.com/MuhammadHananAsghar/ignyt/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/MuhammadHananAsghar/ignyt/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
  </p>
</p>

---

**One binary. Zero config. Replaces mypy, flake8, bandit, vulture, radon, black, and isort.**

Ignyt is a standalone Python code quality engine written in Rust. It performs **type checking**, **security scanning**, **dead code detection**, **complexity analysis**, **format checking**, **auto-fixing**, and **project cleanup** — all in a single binary that runs **10-100x faster** than the tools it replaces.

---

## Why Ignyt?

| Problem | Before (multiple tools) | After (Ignyt) |
|---------|------------------------|----------------|
| Type checking | `mypy` | `ignyt types` |
| Security scanning | `bandit` | `ignyt security` |
| Dead code detection | `vulture` | `ignyt dead` |
| Complexity analysis | `radon` | `ignyt complexity` |
| Import sorting | `isort` | `ignyt fmt` |
| Linting | `flake8` | `ignyt check` |
| Auto-fixing | `black` + manual | `ignyt fix` |
| Cleanup | `pyclean` | `ignyt clean` |
| **Install** | `pip install mypy flake8 bandit vulture radon black isort` | `pip install ignyt` |
| **Config files** | 7 config files | 1 `ignyt.toml` (optional) |
| **Speed** | 30-60 seconds on large projects | **< 1 second** |

## Installation

```bash
pip install ignyt
```

Works on **Linux**, **macOS**, and **Windows**. No Python dependencies. No compilation. Just install and run.

## Quick Start

```bash
# Run all checks on your project
ignyt check src/

# Check a single file
ignyt check app/main.py

# Check everything in current directory
ignyt check .

# Run specific engines
ignyt types src/         # Type checking only
ignyt security src/      # Security scanning only
ignyt dead src/          # Dead code detection only
ignyt complexity src/    # Complexity analysis only

# Auto-fix safe issues
ignyt fix src/

# Get help on a specific rule
ignyt explain SEC001

# Watch mode — re-runs on file changes
ignyt watch src/

# JSON output for CI/CD integration
ignyt check --format json src/

# Remove Python debris (__pycache__, .pyc, .egg-info, etc.)
ignyt clean
ignyt clean --dry-run    # Preview what would be removed
```

## What It Catches

### Security (SEC001-SEC012)

Catches vulnerabilities before they reach production.

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

Finds type errors without running your code.

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

Eliminates unused code that bloats your project.

| Code | Name | Description |
|------|------|-------------|
| DEAD001 | unused-function | Private function never called |
| DEAD002 | unused-class | Private class never referenced |
| DEAD003 | unused-variable | Variable assigned but never used |
| DEAD004 | unused-import | Import never used |
| DEAD005 | unused-argument | Function argument never used |
| DEAD006 | unreachable-code | Code after return/raise/break/continue |

### Complexity (CMPLX001-CMPLX003)

Keeps functions simple and maintainable.

| Code | Name | Description |
|------|------|-------------|
| CMPLX001 | high-cyclomatic | Too many decision branches |
| CMPLX003 | too-many-arguments | Too many function parameters |

### Format (FMT001-FMT002)

Enforces consistent code style.

| Code | Name | Description |
|------|------|-------------|
| FMT001 | unsorted-imports | Imports not sorted alphabetically |
| FMT002 | line-too-long | Line exceeds max length |

## Auto-Fix

Ignyt can automatically fix safe issues:

```bash
ignyt fix src/
```

**What it fixes:**
- Removes unused imports (`DEAD004`)
- Converts `yaml.load()` to `yaml.safe_load()` (`SEC005`)
- Sorts imports alphabetically (`FMT001`)

## Project Cleanup

Remove Python build debris instantly:

```bash
ignyt clean           # Remove all debris
ignyt clean --dry-run # Preview what would be removed
ignyt clean src/      # Clean specific directory
```

**What it removes:** `__pycache__`, `.pyc`, `.pyo`, `.egg-info`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `.nox`, `.eggs`, `.pytype`, `.hypothesis`

## Configuration

Zero configuration required. Optionally create an `ignyt.toml` in your project root:

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

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install Ignyt
  run: pip install ignyt

- name: Run code quality checks
  run: ignyt check --format json src/
```

### Pre-commit Hook

```bash
#!/bin/sh
ignyt check . && ignyt clean --dry-run
```

## Performance

Ignyt is built for speed:

- **Rayon** — parallel file analysis across all CPU cores
- **rustpython-parser** — zero-copy Python AST parsing
- **LTO + single codegen unit** — maximum binary optimization
- **Zero dependencies** — no Python runtime overhead

## Architecture

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

## License

MIT
