//! # ignyt-config
//!
//! Parser and types for the `ignyt.toml` configuration file. Provides
//! sensible defaults so Ignyt works out of the box with zero configuration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ignyt_diagnostics::IgnytError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Root configuration parsed from `ignyt.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnytConfig {
    pub ignyt: IgnytSection,
}

// ---------------------------------------------------------------------------
// [ignyt] section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnytSection {
    /// Target Python version (e.g. "3.11").
    pub python: String,
    /// Source directories to analyze.
    pub src: Vec<String>,
    /// Glob patterns to exclude from analysis.
    pub exclude: Vec<String>,
    /// Formatter settings.
    pub fmt: FmtConfig,
    /// Type checker settings.
    pub types: TypesConfig,
    /// Security scanner settings.
    pub security: SecurityConfig,
    /// Dead code detector settings.
    pub dead: DeadConfig,
    /// Complexity analyzer settings.
    pub complexity: ComplexityConfig,
    /// Per-rule severity overrides.
    pub rules: RulesConfig,
}

impl Default for IgnytSection {
    fn default() -> Self {
        Self {
            python: "3.11".to_string(),
            src: vec!["src/".to_string(), "tests/".to_string()],
            exclude: vec![
                "migrations/".to_string(),
                "*.pyi".to_string(),
                "*_pb2.py".to_string(),
                "**/generated/**".to_string(),
            ],
            fmt: FmtConfig::default(),
            types: TypesConfig::default(),
            security: SecurityConfig::default(),
            dead: DeadConfig::default(),
            complexity: ComplexityConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// [ignyt.fmt]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct FmtConfig {
    pub line_length: usize,
    pub quote_style: QuoteStyle,
    pub indent_style: IndentStyle,
}

impl Default for FmtConfig {
    fn default() -> Self {
        Self {
            line_length: 88,
            quote_style: QuoteStyle::Double,
            indent_style: IndentStyle::Space,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuoteStyle {
    Single,
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndentStyle {
    Space,
    Tab,
}

// ---------------------------------------------------------------------------
// [ignyt.types]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct TypesConfig {
    pub strict: bool,
    pub ignore_missing_imports: bool,
    pub check_untyped_defs: bool,
    pub warn_return_any: bool,
    pub error_on: Vec<String>,
}

impl Default for TypesConfig {
    fn default() -> Self {
        Self {
            strict: false,
            ignore_missing_imports: false,
            check_untyped_defs: true,
            warn_return_any: true,
            error_on: vec![
                "missing-return".to_string(),
                "incompatible-types".to_string(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// [ignyt.security]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct SecurityConfig {
    pub level: SecurityLevel,
    pub ignore: Vec<String>,
    pub scan_deps: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Medium,
            ignore: vec![],
            scan_deps: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Paranoid,
}

// ---------------------------------------------------------------------------
// [ignyt.dead]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct DeadConfig {
    pub min_confidence: u8,
    pub ignore_names: Vec<String>,
    pub ignore_decorators: Vec<String>,
}

impl Default for DeadConfig {
    fn default() -> Self {
        Self {
            min_confidence: 60,
            ignore_names: vec![
                "_*".to_string(),
                "setUp".to_string(),
                "tearDown".to_string(),
            ],
            ignore_decorators: vec![
                "@app.route".to_string(),
                "@pytest.fixture".to_string(),
                "@celery.task".to_string(),
                "@click.command".to_string(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// [ignyt.complexity]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ComplexityConfig {
    pub max_cyclomatic: usize,
    pub max_cognitive: usize,
    pub max_lines: usize,
    pub max_args: usize,
    pub overrides: HashMap<String, ComplexityOverride>,
}

impl Default for ComplexityConfig {
    fn default() -> Self {
        Self {
            max_cyclomatic: 10,
            max_cognitive: 15,
            max_lines: 50,
            max_args: 5,
            overrides: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ComplexityOverride {
    pub max_cyclomatic: Option<usize>,
    pub max_cognitive: Option<usize>,
    pub max_lines: Option<usize>,
    pub max_args: Option<usize>,
}

// ---------------------------------------------------------------------------
// [ignyt.rules]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RulesConfig {
    pub error: Vec<String>,
    pub warn: Vec<String>,
    pub skip: Vec<String>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl IgnytConfig {
    /// Load configuration from a `ignyt.toml` file path.
    /// Returns defaults if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, IgnytError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(|e| IgnytError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;

        Self::parse(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self, IgnytError> {
        toml::from_str(content).map_err(|e| IgnytError::ConfigError {
            message: e.to_string(),
        })
    }

    /// Search upward from `start_dir` for a `ignyt.toml` file and load it.
    pub fn discover(start_dir: &Path) -> Result<(Self, Option<PathBuf>), IgnytError> {
        let mut dir = start_dir.to_path_buf();
        loop {
            let candidate = dir.join("ignyt.toml");
            if candidate.exists() {
                let config = Self::load(&candidate)?;
                return Ok((config, Some(candidate)));
            }
            if !dir.pop() {
                break;
            }
        }
        Ok((Self::default(), None))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IgnytConfig::default();
        assert_eq!(config.ignyt.python, "3.11");
        assert_eq!(config.ignyt.fmt.line_length, 88);
        assert_eq!(config.ignyt.complexity.max_cyclomatic, 10);
        assert!(!config.ignyt.types.strict);
        assert_eq!(config.ignyt.dead.min_confidence, 60);
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
[ignyt]
python = "3.12"
src = ["app/"]
"#;
        let config = IgnytConfig::parse(toml).unwrap();
        assert_eq!(config.ignyt.python, "3.12");
        assert_eq!(config.ignyt.src, vec!["app/"]);
        // defaults should still apply for unspecified sections
        assert_eq!(config.ignyt.fmt.line_length, 88);
    }

    #[test]
    fn test_parse_full_toml() {
        let toml = r#"
[ignyt]
python = "3.11"
src = ["src/", "tests/"]
exclude = ["migrations/"]

[ignyt.fmt]
line-length = 120
quote-style = "single"
indent-style = "tab"

[ignyt.types]
strict = true
ignore-missing-imports = true
check-untyped-defs = false
warn-return-any = false
error-on = ["missing-return"]

[ignyt.security]
level = "high"
ignore = ["SEC007"]
scan-deps = false

[ignyt.dead]
min-confidence = 80
ignore-names = ["_*"]
ignore-decorators = ["@app.route"]

[ignyt.complexity]
max-cyclomatic = 15
max-cognitive = 20
max-lines = 100
max-args = 8
"#;
        let config = IgnytConfig::parse(toml).unwrap();
        assert_eq!(config.ignyt.fmt.line_length, 120);
        assert_eq!(config.ignyt.fmt.quote_style, QuoteStyle::Single);
        assert_eq!(config.ignyt.fmt.indent_style, IndentStyle::Tab);
        assert!(config.ignyt.types.strict);
        assert_eq!(config.ignyt.security.level, SecurityLevel::High);
        assert_eq!(config.ignyt.dead.min_confidence, 80);
        assert_eq!(config.ignyt.complexity.max_cyclomatic, 15);
    }

    #[test]
    fn test_parse_invalid_toml() {
        let result = IgnytConfig::parse("this is not valid toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_file_returns_defaults() {
        let config = IgnytConfig::load(Path::new("/nonexistent/ignyt.toml")).unwrap();
        assert_eq!(config.ignyt.python, "3.11");
    }

    #[test]
    fn test_rules_config() {
        let toml = r#"
[ignyt.rules]
error = ["SEC001", "TYPE001"]
warn  = ["DEAD001"]
skip  = ["SEC101"]
"#;
        let config = IgnytConfig::parse(toml).unwrap();
        assert_eq!(config.ignyt.rules.error, vec!["SEC001", "TYPE001"]);
        assert_eq!(config.ignyt.rules.warn, vec!["DEAD001"]);
        assert_eq!(config.ignyt.rules.skip, vec!["SEC101"]);
    }
}
