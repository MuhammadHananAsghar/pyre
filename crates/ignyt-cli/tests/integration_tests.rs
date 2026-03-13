//! CLI integration tests.
//!
//! These tests build and run the `ignyt` binary against Python fixture files
//! in `tests/fixtures/`. They exercise the full pipeline: file discovery →
//! parsing → analysis → output rendering.

use assert_cmd::Command;
use predicates::prelude::*;
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
