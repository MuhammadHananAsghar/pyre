//! CLI integration tests.
//!
//! These tests build and run the `ignyt` binary against Python fixture files
//! in `tests/fixtures/`. They exercise the full pipeline: file discovery →
//! parsing → analysis → output rendering.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;

/// Path to the shared test fixtures directory (repo root / tests / fixtures).
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()
        .expect("fixtures directory must exist")
}

fn fixture(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

/// Build a `ignyt check` command targeting a fixture.
fn ignyt_check(fixture_name: &str) -> Command {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("check").arg(fixture(fixture_name));
    cmd
}

// =========================================================================
// Easy — Clean code (exit 0, no diagnostics)
// =========================================================================

#[test]
fn test_easy_clean_code_passes() {
    ignyt_check("easy_clean.py")
        .assert()
        .success()
        .stdout(predicate::str::contains("All checks passed"));
}

// =========================================================================
// Easy — Unused imports
// =========================================================================

#[test]
fn test_easy_unused_imports_detected() {
    ignyt_check("easy_unused_imports.py")
        .assert()
        .stdout(predicate::str::contains("DEAD004"));
}

// =========================================================================
// Easy — Missing annotations
// =========================================================================

#[test]
fn test_easy_missing_annotations() {
    ignyt_check("easy_missing_annotations.py")
        .assert()
        .stdout(predicate::str::contains("TYPE003"));
}

// =========================================================================
// Easy — Unsorted imports
// =========================================================================

#[test]
fn test_easy_unsorted_imports() {
    ignyt_check("easy_unsorted_imports.py")
        .assert()
        .stdout(predicate::str::contains("FMT001"));
}

// =========================================================================
// Medium — Security scan
// =========================================================================

#[test]
fn test_medium_security_eval() {
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC011"));
}

#[test]
fn test_medium_security_hardcoded_password() {
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC001"));
}

#[test]
fn test_medium_security_yaml_load() {
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC005"));
}

#[test]
fn test_medium_security_pickle() {
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC004"));
}

#[test]
fn test_medium_security_weak_crypto() {
    // SEC008 — hashlib.md5()
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC008"));
}

#[test]
fn test_medium_security_shell_injection() {
    ignyt_check("medium_security.py")
        .assert()
        .stdout(predicate::str::contains("SEC003"));
}

// =========================================================================
// Medium — Dead code
// =========================================================================

#[test]
fn test_medium_dead_unused_private_function() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD001"));
}

#[test]
fn test_medium_dead_unused_import() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD004"));
}

#[test]
fn test_medium_dead_unreachable_code() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD006"));
}

#[test]
fn test_medium_dead_unused_variable() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD003"));
}

// =========================================================================
// Medium — Complexity
// =========================================================================

#[test]
fn test_medium_complexity_too_many_args() {
    ignyt_check("medium_complexity.py")
        .assert()
        .stdout(predicate::str::contains("CMPLX003"));
}

// =========================================================================
// Medium — Type errors
// =========================================================================

#[test]
fn test_medium_type_missing_return() {
    ignyt_check("medium_type_errors.py")
        .assert()
        .stdout(predicate::str::contains("TYPE001"));
}

#[test]
fn test_medium_type_incompatible_default() {
    ignyt_check("medium_type_errors.py")
        .assert()
        .stdout(predicate::str::contains("TYPE002"));
}

#[test]
fn test_medium_type_missing_annotation() {
    ignyt_check("medium_type_errors.py")
        .assert()
        .stdout(predicate::str::contains("TYPE003"));
}

#[test]
fn test_medium_type_optional_not_checked() {
    ignyt_check("medium_type_errors.py")
        .assert()
        .stdout(predicate::str::contains("TYPE007"));
}

// =========================================================================
// Hard — Mixed issues (all engines fire)
// =========================================================================

#[test]
fn test_hard_mixed_has_security_issues() {
    let assert = ignyt_check("hard_mixed_issues.py").assert();
    assert
        .stdout(predicate::str::contains("SEC002"))
        .stdout(predicate::str::contains("SEC009"))
        .stdout(predicate::str::contains("SEC011"));
}

#[test]
fn test_hard_mixed_has_type_issues() {
    let assert = ignyt_check("hard_mixed_issues.py").assert();
    assert
        .stdout(predicate::str::contains("TYPE001"))
        .stdout(predicate::str::contains("TYPE002"))
        .stdout(predicate::str::contains("TYPE003"));
}

#[test]
fn test_hard_mixed_has_dead_code() {
    let assert = ignyt_check("hard_mixed_issues.py").assert();
    assert
        .stdout(predicate::str::contains("DEAD001"))
        .stdout(predicate::str::contains("DEAD004"));
}

#[test]
fn test_hard_mixed_exits_with_error_code() {
    ignyt_check("hard_mixed_issues.py")
        .assert()
        .code(predicate::eq(1));
}

// =========================================================================
// Hard — Deep security audit
// =========================================================================

#[test]
fn test_hard_security_deep_sql_injection() {
    ignyt_check("hard_security_deep.py")
        .assert()
        .stdout(predicate::str::contains("SEC002"));
}

#[test]
fn test_hard_security_deep_hardcoded_token() {
    ignyt_check("hard_security_deep.py")
        .assert()
        .stdout(predicate::str::contains("SEC009"));
}

#[test]
fn test_hard_security_deep_path_traversal() {
    ignyt_check("hard_security_deep.py")
        .assert()
        .stdout(predicate::str::contains("SEC012"));
}

#[test]
fn test_hard_security_deep_hardcoded_credential() {
    ignyt_check("hard_security_deep.py")
        .assert()
        .stdout(predicate::str::contains("SEC001"));
}

#[test]
fn test_hard_security_deep_pickle() {
    ignyt_check("hard_security_deep.py")
        .assert()
        .stdout(predicate::str::contains("SEC004"));
}

// =========================================================================
// JSON output mode
// =========================================================================

#[test]
fn test_json_output_format() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("check")
        .arg("--format")
        .arg("json")
        .arg(fixture("easy_unused_imports.py"));

    let output = cmd.output().expect("command must run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The header line is printed to stdout before JSON. Find the JSON object.
    let json_start = stdout.find('{').expect("must contain JSON");
    let json_str = &stdout[json_start..];

    let parsed: serde_json::Value =
        serde_json::from_str(json_str).expect("output must be valid JSON");

    assert!(parsed["diagnostics"].is_array());
    assert!(parsed["summary"]["total"].is_number());
    assert!(parsed["summary"]["file_count"].is_number());
}

// =========================================================================
// Subcommand-specific tests
// =========================================================================

#[test]
fn test_security_subcommand_only_security() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("security").arg(fixture("medium_security.py"));

    let output = cmd.output().expect("command must run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("SEC"));
    assert!(!stdout.contains("TYPE003"));
    assert!(!stdout.contains("DEAD004"));
}

#[test]
fn test_types_subcommand_only_types() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("types").arg(fixture("medium_type_errors.py"));

    let output = cmd.output().expect("command must run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("TYPE"));
    assert!(!stdout.contains("SEC011"));
    assert!(!stdout.contains("DEAD004"));
}

#[test]
fn test_dead_subcommand_only_dead() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("dead").arg(fixture("medium_dead_code.py"));

    let output = cmd.output().expect("command must run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("DEAD"));
    assert!(!stdout.contains("TYPE003"));
    assert!(!stdout.contains("SEC011"));
}

// =========================================================================
// New rules — DEAD002, DEAD005
// =========================================================================

#[test]
fn test_medium_dead_unused_class() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD002"));
}

#[test]
fn test_medium_dead_unused_argument() {
    ignyt_check("medium_dead_code.py")
        .assert()
        .stdout(predicate::str::contains("DEAD005"));
}

// =========================================================================
// New rules — TYPE005 (mutable default)
// =========================================================================

#[test]
fn test_medium_type_mutable_default() {
    ignyt_check("medium_type_errors.py")
        .assert()
        .stdout(predicate::str::contains("TYPE005"));
}

// =========================================================================
// Explain subcommand
// =========================================================================

#[test]
fn test_explain_known_rule() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("explain").arg("SEC001");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hardcoded-password"))
        .stdout(predicate::str::contains("Critical"));
}

#[test]
fn test_explain_unknown_rule() {
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("explain").arg("FAKE999");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Unknown rule code"));
}

// =========================================================================
// Single file and dot-path support
// =========================================================================

#[test]
fn test_single_file_check() {
    // Passing a single .py file directly should work.
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("check").arg(fixture("easy_unused_imports.py"));

    cmd.assert()
        .stdout(predicate::str::contains("DEAD004"))
        .stdout(predicate::str::contains("file"));
}

#[test]
fn test_dot_path_checks_directory() {
    // Running with "." from the fixtures directory should find Python files.
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("check").arg(fixtures_dir());

    cmd.assert().stdout(predicate::str::contains("file"));
}

// =========================================================================
// Clean subcommand
// =========================================================================

#[test]
fn test_clean_dry_run_finds_pycache() {
    // Create a temp directory with __pycache__ inside it.
    let tmp = std::env::temp_dir().join("ignyt_test_clean_dry");
    let pycache = tmp.join("__pycache__");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&pycache).unwrap();
    fs::write(pycache.join("mod.cpython-311.pyc"), b"fake").unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("clean").arg("--dry-run").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("would remove"))
        .stdout(predicate::str::contains("__pycache__"));

    // Dry run should NOT delete the directory.
    assert!(
        pycache.exists(),
        "__pycache__ should still exist after dry run"
    );

    // Cleanup.
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_clean_removes_pycache() {
    // Create a temp directory with __pycache__ and a stray .pyc file.
    let tmp = std::env::temp_dir().join("ignyt_test_clean_real");
    let pycache = tmp.join("__pycache__");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&pycache).unwrap();
    fs::write(pycache.join("mod.cpython-311.pyc"), b"fake").unwrap();
    fs::write(tmp.join("stray.pyc"), b"stray").unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("clean").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    // Both should be gone.
    assert!(!pycache.exists(), "__pycache__ should be deleted");
    assert!(
        !tmp.join("stray.pyc").exists(),
        "stray .pyc should be deleted"
    );

    // Cleanup.
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_clean_removes_pytest_cache() {
    let tmp = std::env::temp_dir().join("ignyt_test_clean_pytest");
    let pytest_cache = tmp.join(".pytest_cache");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&pytest_cache).unwrap();
    fs::write(pytest_cache.join("README.md"), b"pytest cache").unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("clean").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    assert!(!pytest_cache.exists(), ".pytest_cache should be deleted");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_clean_removes_egg_info() {
    let tmp = std::env::temp_dir().join("ignyt_test_clean_egg");
    let egg_info = tmp.join("mypackage.egg-info");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&egg_info).unwrap();
    fs::write(egg_info.join("PKG-INFO"), b"info").unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("clean").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    assert!(!egg_info.exists(), ".egg-info should be deleted");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_clean_empty_directory_no_crash() {
    let tmp = std::env::temp_dir().join("ignyt_test_clean_empty");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("clean").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0 director"))
        .stdout(predicate::str::contains("0 file"));

    let _ = fs::remove_dir_all(&tmp);
}

// =========================================================================
// Gitignore validation
// =========================================================================

#[test]
fn test_gitignore_missing_file() {
    // A directory with no .gitignore should report GIT001.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_missing");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert()
        .code(predicate::eq(1))
        .stdout(predicate::str::contains("GIT001"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_good_file_passes() {
    // A well-formed .gitignore should produce no errors.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_good");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
__pycache__/
*.pyc
*.pyo
.env
.env.local
*.pem
*.key
*.egg-info/
dist/
build/
venv/
.venv/
.pytest_cache/
.mypy_cache/
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("looks good"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_missing_python_patterns() {
    // A .gitignore missing essential patterns should report GIT002.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_missing_py");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
.env
.env.local
*.pem
*.key
*.log
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert().stdout(predicate::str::contains("GIT002"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_duplicate_entries() {
    // Duplicate entries should report GIT003.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_dups");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
__pycache__/
*.pyc
.env
.env.local
*.pem
*.key
*.egg-info/
dist/
build/
venv/
__pycache__/
dist/
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert().stdout(predicate::str::contains("GIT003"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_trailing_whitespace() {
    // Trailing whitespace should report GIT004.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_ws");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "__pycache__/  \n*.pyc\n.env\n.env.local\n*.pem\n*.key\n*.egg-info/\ndist/\nbuild/\nvenv/\n";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert().stdout(predicate::str::contains("GIT004"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_overly_broad_pattern() {
    // Overly broad patterns like *.py should report GIT005.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_broad");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
__pycache__/
*.pyc
*.py
.env
.env.local
*.pem
*.key
*.egg-info/
dist/
build/
venv/
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert()
        .code(predicate::eq(1))
        .stdout(predicate::str::contains("GIT005"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_missing_secrets() {
    // Missing .env and secrets patterns should report GIT006.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_secrets");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
__pycache__/
*.pyc
*.egg-info/
dist/
build/
venv/
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert().stdout(predicate::str::contains("GIT006"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_invalid_glob() {
    // *** pattern should report GIT004.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_glob");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "\
__pycache__/
*.pyc
.env
.env.local
*.pem
*.key
*.egg-info/
dist/
build/
venv/
***/foo
";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert().stdout(predicate::str::contains("GIT004"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_star_alone_is_critical() {
    // A lone `*` should report GIT005 as critical.
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_star");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let content = "*\n";
    fs::write(tmp.join(".gitignore"), content).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg(&tmp);

    cmd.assert()
        .code(predicate::eq(1))
        .stdout(predicate::str::contains("GIT005"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_init_creates_file() {
    let tmp = std::env::temp_dir().join("ignyt_test_gitignore_init");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("gitignore").arg("--init").arg(&tmp);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("created .gitignore"));

    // The file should exist now.
    assert!(tmp.join(".gitignore").exists());

    // Read it and check it has essential patterns.
    let content = fs::read_to_string(tmp.join(".gitignore")).unwrap();
    assert!(content.contains("__pycache__/"));
    assert!(content.contains("*.py[cod]"));
    assert!(content.contains(".env"));
    assert!(content.contains("venv/"));
    assert!(content.contains("dist/"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_gitignore_explain_rules() {
    // Verify GIT rules show up in explain.
    let mut cmd = Command::cargo_bin("ignyt").expect("binary must build");
    cmd.arg("explain").arg("GIT001");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("missing-gitignore"));

    let mut cmd2 = Command::cargo_bin("ignyt").expect("binary must build");
    cmd2.arg("explain").arg("GIT005");

    cmd2.assert()
        .success()
        .stdout(predicate::str::contains("overly-broad-pattern"));
}
