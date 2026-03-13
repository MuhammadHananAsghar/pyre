//! Source map utilities for mapping byte offsets to line/column positions.

/// Maps byte offsets within a source string to line/column numbers.
#[derive(Debug)]
pub struct SourceMap {
    /// Byte offsets where each line starts (0-indexed lines internally).
    line_starts: Vec<usize>,
}

impl SourceMap {
    /// Build a source map from the given source text.
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    /// Convert a byte offset to a 1-based (line, column) pair.
    /// Returns `None` if the offset is out of bounds.
    pub fn offset_to_line_col(&self, offset: usize) -> Option<(usize, usize)> {
        let line_idx = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .checked_sub(1)?;

        let col = offset - self.line_starts[line_idx];
        Some((line_idx + 1, col + 1))
    }

    /// Return the total number of lines.
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_line() {
        let map = SourceMap::new("hello");
        assert_eq!(map.offset_to_line_col(0), Some((1, 1)));
        assert_eq!(map.offset_to_line_col(4), Some((1, 5)));
        assert_eq!(map.line_count(), 1);
    }

    #[test]
    fn test_multi_line() {
        let source = "line1\nline2\nline3";
        let map = SourceMap::new(source);
        assert_eq!(map.line_count(), 3);
        assert_eq!(map.offset_to_line_col(0), Some((1, 1))); // 'l' in line1
        assert_eq!(map.offset_to_line_col(6), Some((2, 1))); // 'l' in line2
        assert_eq!(map.offset_to_line_col(12), Some((3, 1))); // 'l' in line3
    }

    #[test]
    fn test_empty_source() {
        let map = SourceMap::new("");
        assert_eq!(map.line_count(), 1);
        assert_eq!(map.offset_to_line_col(0), Some((1, 1)));
    }
}
