//! # ignyt-diagnostics
//!
//! Shared diagnostic types, severity levels, and error reporting for the Ignyt
//! code quality engine. Every analysis crate produces [`Diagnostic`] values
//! that the CLI renders to the terminal.

use std::fmt;
use std::path::PathBuf;

use miette::SourceSpan;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// How severe a diagnostic finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational hint — no action required.
    Hint,
    /// Something looks suspicious but may be intentional.
    Warning,
    /// A definite problem that should be fixed.
    Error,
    /// A security-critical finding that must be addressed.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hint => write!(f, "hint"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// Which analysis engine produced the diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Type,
    Dead,
    Security,
    Complexity,
    Format,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type => write!(f, "types"),
            Self::Dead => write!(f, "dead"),
            Self::Security => write!(f, "security"),
            Self::Complexity => write!(f, "complexity"),
            Self::Format => write!(f, "fmt"),
        }
    }
}

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

/// A source location within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Absolute or project-relative file path.
    pub path: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number.
    pub column: usize,
    /// Optional byte-offset span for rich error rendering.
    pub span: Option<(usize, usize)>,
}

impl Location {
    pub fn new(path: impl Into<PathBuf>, line: usize, column: usize) -> Self {
        Self {
            path: path.into(),
            line,
            column,
            span: None,
        }
    }

    pub fn with_span(mut self, offset: usize, length: usize) -> Self {
        self.span = Some((offset, length));
        self
    }

    /// Convert the optional span to a [`miette::SourceSpan`].
    pub fn source_span(&self) -> Option<SourceSpan> {
        self.span
            .map(|(offset, len)| SourceSpan::new(offset.into(), len))
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.path.display(), self.line, self.column)
    }
}

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

/// A single finding produced by any Ignyt analysis engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Rule code, e.g. `TYPE001`, `SEC002`, `DEAD004`.
    pub code: String,
    /// Human-readable rule name, e.g. `missing-return`.
    pub name: String,
    /// One-line description of the finding.
    pub message: String,
    /// Where in the source the finding was detected.
    pub location: Location,
    /// Severity level.
    pub severity: Severity,
    /// Which engine produced this diagnostic.
    pub category: Category,
    /// Optional suggestion for how to fix it.
    pub suggestion: Option<String>,
    /// Whether this finding can be auto-fixed by `ignyt fix`.
    pub fixable: bool,
}

impl Diagnostic {
    /// Create a new diagnostic with required fields.
    pub fn new(
        code: impl Into<String>,
        name: impl Into<String>,
        message: impl Into<String>,
        location: Location,
        severity: Severity,
        category: Category,
    ) -> Self {
        Self {
            code: code.into(),
            name: name.into(),
            message: message.into(),
            location,
            severity,
            category,
            suggestion: None,
            fixable: false,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_fixable(mut self, fixable: bool) -> Self {
        self.fixable = fixable;
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8} {:<30} {}", self.code, self.location, self.message,)
    }
}

// ---------------------------------------------------------------------------
// DiagnosticBag — collector used during analysis
// ---------------------------------------------------------------------------

/// Accumulates diagnostics during an analysis pass.
#[derive(Debug, Default, Clone)]
pub struct DiagnosticBag {
    diagnostics: Vec<Diagnostic>,
}

impl DiagnosticBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn extend(&mut self, other: DiagnosticBag) {
        self.diagnostics.extend(other.diagnostics);
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn len(&self) -> usize {
        self.diagnostics.len()
    }

    /// Consume and return diagnostics sorted by file path, then line number.
    pub fn into_sorted(mut self) -> Vec<Diagnostic> {
        self.diagnostics.sort_by(|a, b| {
            a.location
                .path
                .cmp(&b.location.path)
                .then(a.location.line.cmp(&b.location.line))
                .then(a.location.column.cmp(&b.location.column))
        });
        self.diagnostics
    }

    /// Return a reference to all collected diagnostics.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Count diagnostics by severity.
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == severity)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Top-level error type shared across Ignyt crates.
#[derive(Debug, thiserror::Error)]
pub enum IgnytError {
    #[error("failed to read file: {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse Python source: {path}")]
    ParseError { path: PathBuf, message: String },

    #[error("invalid configuration: {message}")]
    ConfigError { message: String },

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Convenient Result alias used throughout Ignyt.
pub type IgnytResult<T> = Result<T, IgnytError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Hint < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Hint.to_string(), "hint");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_location_display() {
        let loc = Location::new("src/main.py", 42, 5);
        assert_eq!(loc.to_string(), "src/main.py:42:5");
    }

    #[test]
    fn test_location_with_span() {
        let loc = Location::new("test.py", 1, 1).with_span(10, 5);
        assert!(loc.span.is_some());
        let span = loc.source_span().unwrap();
        assert_eq!(span.offset(), 10);
        assert_eq!(span.len(), 5);
    }

    #[test]
    fn test_diagnostic_display() {
        let diag = Diagnostic::new(
            "TYPE001",
            "missing-return",
            "Function missing return statement",
            Location::new("src/api.py", 10, 1),
            Severity::Error,
            Category::Type,
        );
        let output = diag.to_string();
        assert!(output.contains("TYPE001"));
        assert!(output.contains("src/api.py:10:1"));
        assert!(output.contains("Function missing return statement"));
    }

    #[test]
    fn test_diagnostic_builder() {
        let diag = Diagnostic::new(
            "SEC002",
            "sql-injection",
            "Possible SQL injection",
            Location::new("db.py", 5, 1),
            Severity::Critical,
            Category::Security,
        )
        .with_suggestion("Use parameterized queries")
        .with_fixable(false);

        assert_eq!(
            diag.suggestion.as_deref(),
            Some("Use parameterized queries")
        );
        assert!(!diag.fixable);
    }

    #[test]
    fn test_diagnostic_bag_operations() {
        let mut bag = DiagnosticBag::new();
        assert!(bag.is_empty());

        bag.push(Diagnostic::new(
            "DEAD001",
            "unused-function",
            "never called",
            Location::new("b.py", 20, 1),
            Severity::Warning,
            Category::Dead,
        ));
        bag.push(Diagnostic::new(
            "TYPE001",
            "missing-return",
            "missing return",
            Location::new("a.py", 10, 1),
            Severity::Error,
            Category::Type,
        ));

        assert_eq!(bag.len(), 2);
        assert_eq!(bag.count_by_severity(Severity::Error), 1);
        assert_eq!(bag.count_by_severity(Severity::Warning), 1);

        // into_sorted should order by path, then line
        let sorted = bag.into_sorted();
        assert_eq!(sorted[0].location.path, Path::new("a.py"));
        assert_eq!(sorted[1].location.path, Path::new("b.py"));
    }
}
