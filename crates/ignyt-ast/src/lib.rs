//! # ignyt-ast
//!
//! Shared Python AST parser built on `rustpython-parser`. All analysis crates
//! consume the types defined here. Provides source-map tracking and a module
//! graph builder for cross-file analysis.

pub mod source;

use std::path::{Path, PathBuf};

use ignyt_diagnostics::{IgnytError, IgnytResult, Location};
use rustpython_parser::{self as parser, ast};
use source::SourceMap;

// Re-export the AST types so downstream crates don't depend on rustpython directly.
pub use rustpython_parser::ast::*;

// ---------------------------------------------------------------------------
// SourceFile — a parsed Python module
// ---------------------------------------------------------------------------

/// A parsed Python source file with its AST and metadata.
#[derive(Debug)]
pub struct SourceFile {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Raw source text (kept for span-based error reporting).
    pub source: String,
    /// The parsed module AST.
    pub module: ast::ModModule,
    /// Source map for byte-offset → line/column conversion.
    pub source_map: SourceMap,
}

impl SourceFile {
    /// Parse a Python file from disk.
    pub fn parse_file(path: &Path) -> IgnytResult<Self> {
        let source = std::fs::read_to_string(path).map_err(|e| IgnytError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::parse_source(path.to_path_buf(), source)
    }

    /// Parse Python source from a string (useful for testing).
    pub fn parse_source(path: PathBuf, source: String) -> IgnytResult<Self> {
        let module = parser::parse(&source, parser::Mode::Module, "<module>").map_err(|e| {
            IgnytError::ParseError {
                path: path.clone(),
                message: e.to_string(),
            }
        })?;

        // Extract the Module variant from the parsed AST.
        let module = match module {
            ast::Mod::Module(m) => m,
            _ => {
                return Err(IgnytError::ParseError {
                    path,
                    message: "expected a module, got an expression".to_string(),
                });
            }
        };

        let source_map = SourceMap::new(&source);

        Ok(Self {
            path,
            source,
            module,
            source_map,
        })
    }

    /// Get the top-level statements of this module.
    pub fn body(&self) -> &[ast::Stmt] {
        &self.module.body
    }

    /// Convert a byte offset from the AST into a [`Location`].
    pub fn location_from_offset(&self, offset: u32) -> Location {
        let (line, col) = self
            .source_map
            .offset_to_line_col(offset as usize)
            .unwrap_or((1, 1));
        Location::new(&self.path, line, col)
    }

    /// Convert an AST node's `TextRange` start into a [`Location`].
    pub fn location_from_range(&self, range: &rustpython_parser::text_size::TextRange) -> Location {
        self.location_from_offset(range.start().to_u32())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_source() {
        let source = r#"
def hello(name: str) -> str:
    return f"Hello, {name}!"

x: int = 42
"#;
        let file = SourceFile::parse_source(PathBuf::from("test.py"), source.to_string()).unwrap();
        assert_eq!(file.path, PathBuf::from("test.py"));
        assert!(!file.body().is_empty());
    }

    #[test]
    fn test_parse_import_statements() {
        let source = r#"
import os
from pathlib import Path
from typing import List, Optional
"#;
        let file =
            SourceFile::parse_source(PathBuf::from("imports.py"), source.to_string()).unwrap();
        assert_eq!(file.body().len(), 3);
    }

    #[test]
    fn test_parse_class_definition() {
        let source = r#"
class User:
    name: str
    age: int

    def greet(self) -> str:
        return f"Hi, I'm {self.name}"
"#;
        let file = SourceFile::parse_source(PathBuf::from("model.py"), source.to_string()).unwrap();
        assert_eq!(file.body().len(), 1);
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let source = "def broken(:\n    pass";
        let result = SourceFile::parse_source(PathBuf::from("bad.py"), source.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_file() {
        let file = SourceFile::parse_source(PathBuf::from("empty.py"), String::new()).unwrap();
        assert!(file.body().is_empty());
    }

    #[test]
    fn test_location_from_offset() {
        let source = "import os\nx = 42\n";
        let file = SourceFile::parse_source(PathBuf::from("test.py"), source.to_string()).unwrap();
        let loc = file.location_from_offset(0);
        assert_eq!(loc.line, 1);
        assert_eq!(loc.column, 1);

        let loc2 = file.location_from_offset(10); // 'x' on line 2
        assert_eq!(loc2.line, 2);
        assert_eq!(loc2.column, 1);
    }
}
