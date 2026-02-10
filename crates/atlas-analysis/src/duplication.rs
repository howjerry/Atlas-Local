//! Token-based code duplication detection
//!
//! 使用 tree-sitter 葉節點提取 token，透過 Rabin-Karp rolling hash
//! 偵測 Type I (完全相同) 和 Type II (變數重新命名) 的程式碼重複區塊。

use std::collections::HashMap;
use tree_sitter::{Node, Tree};

/// 標準化的 token 表示
///
/// 將識別符號、數字、字串常量標準化以偵測 Type II clones
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedToken {
    /// Token 類型 (tree-sitter node kind)
    pub kind: String,
    /// 標準化後的值
    /// - 識別符號 → "$ID"
    /// - 數字常量 → "$NUM"
    /// - 字串常量 → "$STR"
    /// - 其他保持原值
    pub value: String,
    /// 原始碼中的行號 (0-based)
    pub line: usize,
    /// 原始碼中的列號 (0-based)
    pub column: usize,
}

/// Token 化的檔案
#[derive(Debug, Clone)]
pub struct TokenizedFile {
    /// 檔案路徑
    pub file_path: String,
    /// 標準化的 token 序列
    pub tokens: Vec<NormalizedToken>,
}

/// 重複程式碼區塊資料
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateBlockData {
    /// 檔案 A 路徑
    pub file_a: String,
    /// 檔案 A 中的行範圍 (起始行, 結束行) — 1-based for user display
    pub line_range_a: (usize, usize),
    /// 檔案 B 路徑
    pub file_b: String,
    /// 檔案 B 中的行範圍 (起始行, 結束行) — 1-based for user display
    pub line_range_b: (usize, usize),
    /// Token 數量
    pub token_count: usize,
    /// 行數
    pub line_count: usize,
}

/// 重複檢測結果
#[derive(Debug, Clone, PartialEq)]
pub struct DuplicationResult {
    /// 重複區塊列表
    pub blocks: Vec<DuplicateBlockData>,
    /// 總重複行數
    pub total_duplicated_lines: usize,
    /// 總行數
    pub total_lines: usize,
    /// 重複百分比 (0-100)
    pub duplication_percentage: f64,
}

/// Token-based 重複檢測器
///
/// 使用 Rabin-Karp rolling hash 演算法偵測程式碼重複區塊
pub struct DuplicationDetector {
    /// 最小 token 數量 (小於此數量的區塊不視為重複)
    min_tokens: u32,
    /// Rabin-Karp hash 的基數
    hash_base: u64,
    /// Rabin-Karp hash 的模數 (2^61 - 1, Mersenne prime)
    hash_modulus: u64,
}

impl DuplicationDetector {
    /// 建立新的重複檢測器
    ///
    /// # Arguments
    /// * `min_tokens` - 最小 token 數量閾值
    pub fn new(min_tokens: u32) -> Self {
        Self {
            min_tokens,
            hash_base: 31,
            hash_modulus: (1u64 << 61) - 1, // 2^61 - 1
        }
    }

    /// 將 tree-sitter AST 轉換為標準化 token 序列
    ///
    /// # Arguments
    /// * `tree` - tree-sitter 語法樹
    /// * `source` - 原始碼內容
    /// * `file_path` - 檔案路徑
    pub fn tokenize_file(tree: &Tree, source: &str, file_path: &str) -> TokenizedFile {
        let mut tokens = Vec::new();
        let root = tree.root_node();

        // 遞迴走訪所有葉節點
        Self::collect_leaf_tokens(root, source, &mut tokens);

        TokenizedFile {
            file_path: file_path.to_string(),
            tokens,
        }
    }

    /// 遞迴收集所有葉節點的 token
    fn collect_leaf_tokens(node: Node, source: &str, tokens: &mut Vec<NormalizedToken>) {
        // 如果是葉節點 (沒有子節點)
        if node.child_count() == 0 {
            let kind = node.kind().to_string();
            let raw_value = node.utf8_text(source.as_bytes()).unwrap_or("");

            // 標準化 token 值
            let normalized_value = Self::normalize_token_value(&kind, raw_value);

            let position = node.start_position();
            tokens.push(NormalizedToken {
                kind,
                value: normalized_value,
                line: position.row,
                column: position.column,
            });
        } else {
            // 遞迴處理所有子節點
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                Self::collect_leaf_tokens(child, source, tokens);
            }
        }
    }

    /// 標準化 token 值
    ///
    /// - 識別符號類型 → "$ID"
    /// - 數字常量類型 → "$NUM"
    /// - 字串常量類型 → "$STR"
    /// - 其他保持原值
    fn normalize_token_value(kind: &str, raw_value: &str) -> String {
        let kind_lower = kind.to_lowercase();

        if kind_lower.contains("identifier") {
            "$ID".to_string()
        } else if kind_lower.contains("number")
            || kind_lower.contains("integer")
            || kind_lower.contains("float")
            || kind_lower.contains("decimal") {
            "$NUM".to_string()
        } else if kind_lower.contains("string") {
            "$STR".to_string()
        } else {
            raw_value.to_string()
        }
    }

    /// 偵測重複程式碼區塊
    ///
    /// # Arguments
    /// * `files` - 已 token 化的檔案列表
    pub fn detect(&self, files: &[TokenizedFile]) -> DuplicationResult {
        if files.is_empty() || self.min_tokens == 0 {
            return DuplicationResult {
                blocks: Vec::new(),
                total_duplicated_lines: 0,
                total_lines: 0,
                duplication_percentage: 0.0,
            };
        }

        // 計算總行數
        let total_lines: usize = files.iter().map(|f| {
            if let Some(last) = f.tokens.last() {
                last.line + 1
            } else {
                0
            }
        }).sum();

        // 建立 hash → Vec<(file_index, token_position)> 的對應表
        let mut hash_map: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();

        // 對每個檔案計算 rolling hash
        for (file_idx, file) in files.iter().enumerate() {
            self.compute_rolling_hashes(file_idx, &file.tokens, &mut hash_map);
        }

        // 找出所有重複區塊
        let mut blocks = self.find_duplicate_blocks(files, &hash_map);

        // 合併重疊的區塊
        blocks = Self::merge_overlapping_blocks(blocks);

        // 計算總重複行數
        let total_duplicated_lines = blocks.iter()
            .map(|b| b.line_count)
            .sum::<usize>();

        let duplication_percentage = if total_lines > 0 {
            (total_duplicated_lines as f64 / total_lines as f64) * 100.0
        } else {
            0.0
        };

        DuplicationResult {
            blocks,
            total_duplicated_lines,
            total_lines,
            duplication_percentage,
        }
    }

    /// 使用 Rabin-Karp 演算法計算 rolling hash
    fn compute_rolling_hashes(
        &self,
        file_idx: usize,
        tokens: &[NormalizedToken],
        hash_map: &mut HashMap<u64, Vec<(usize, usize)>>,
    ) {
        let window_size = self.min_tokens as usize;
        if tokens.len() < window_size {
            return;
        }

        // 計算初始視窗的 hash
        let mut current_hash = 0u64;
        let mut power = 1u64;

        for i in 0..window_size {
            let token_hash = self.token_hash(&tokens[i]);
            current_hash = self.add_mod(
                current_hash,
                self.mul_mod(token_hash, power)
            );
            if i < window_size - 1 {
                power = self.mul_mod(power, self.hash_base);
            }
        }

        hash_map.entry(current_hash)
            .or_insert_with(Vec::new)
            .push((file_idx, 0));

        // Rolling hash: 移除最左邊的 token，加入新的 token
        for i in window_size..tokens.len() {
            let old_token_hash = self.token_hash(&tokens[i - window_size]);
            let new_token_hash = self.token_hash(&tokens[i]);

            // 移除舊的 token
            current_hash = self.sub_mod(
                current_hash,
                self.mul_mod(old_token_hash, power)
            );

            // 左移
            current_hash = self.mul_mod(current_hash, self.hash_base);

            // 加入新的 token
            current_hash = self.add_mod(current_hash, new_token_hash);

            hash_map.entry(current_hash)
                .or_insert_with(Vec::new)
                .push((file_idx, i - window_size + 1));
        }
    }

    /// 計算單個 token 的 hash 值
    fn token_hash(&self, token: &NormalizedToken) -> u64 {
        // 簡單的字串 hash (使用標準化後的值)
        let mut hash = 0u64;
        for byte in token.value.bytes() {
            hash = self.add_mod(
                self.mul_mod(hash, self.hash_base),
                byte as u64
            );
        }
        hash
    }

    /// 模運算加法
    #[inline]
    fn add_mod(&self, a: u64, b: u64) -> u64 {
        let sum = (a + b) % self.hash_modulus;
        sum
    }

    /// 模運算減法
    #[inline]
    fn sub_mod(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            (a - b) % self.hash_modulus
        } else {
            ((self.hash_modulus + a) - b) % self.hash_modulus
        }
    }

    /// 模運算乘法
    #[inline]
    fn mul_mod(&self, a: u64, b: u64) -> u64 {
        // 為避免溢位，使用 u128
        ((a as u128 * b as u128) % self.hash_modulus as u128) as u64
    }

    /// 找出所有重複區塊
    fn find_duplicate_blocks(
        &self,
        files: &[TokenizedFile],
        hash_map: &HashMap<u64, Vec<(usize, usize)>>,
    ) -> Vec<DuplicateBlockData> {
        let mut blocks = Vec::new();
        let window_size = self.min_tokens as usize;

        for positions in hash_map.values() {
            if positions.len() < 2 {
                continue; // 沒有重複
            }

            // 檢查所有配對
            for i in 0..positions.len() {
                for j in (i + 1)..positions.len() {
                    let (file_a_idx, pos_a) = positions[i];
                    let (file_b_idx, pos_b) = positions[j];

                    let file_a = &files[file_a_idx];
                    let file_b = &files[file_b_idx];

                    // 驗證 token 序列確實相同 (防止 hash collision)
                    if self.verify_match(
                        &file_a.tokens[pos_a..],
                        &file_b.tokens[pos_b..],
                        window_size,
                    ) {
                        // 嘗試擴展匹配區塊
                        let extended_len = self.extend_match(
                            &file_a.tokens,
                            &file_b.tokens,
                            pos_a,
                            pos_b,
                            window_size,
                        );

                        let block = self.create_block_data(
                            file_a,
                            file_b,
                            pos_a,
                            pos_b,
                            extended_len,
                        );

                        blocks.push(block);
                    }
                }
            }
        }

        blocks
    }

    /// 驗證兩個 token 序列是否匹配
    fn verify_match(
        &self,
        tokens_a: &[NormalizedToken],
        tokens_b: &[NormalizedToken],
        window_size: usize,
    ) -> bool {
        if tokens_a.len() < window_size || tokens_b.len() < window_size {
            return false;
        }

        for i in 0..window_size {
            if tokens_a[i].value != tokens_b[i].value {
                return false;
            }
        }

        true
    }

    /// 擴展匹配區塊 (向前和向後擴展)
    fn extend_match(
        &self,
        tokens_a: &[NormalizedToken],
        tokens_b: &[NormalizedToken],
        pos_a: usize,
        pos_b: usize,
        initial_len: usize,
    ) -> usize {
        let mut len = initial_len;

        // 向後擴展
        while pos_a + len < tokens_a.len()
            && pos_b + len < tokens_b.len()
            && tokens_a[pos_a + len].value == tokens_b[pos_b + len].value {
            len += 1;
        }

        len
    }

    /// 建立重複區塊資料
    fn create_block_data(
        &self,
        file_a: &TokenizedFile,
        file_b: &TokenizedFile,
        pos_a: usize,
        pos_b: usize,
        token_count: usize,
    ) -> DuplicateBlockData {
        let start_line_a = file_a.tokens[pos_a].line;
        let end_line_a = file_a.tokens[pos_a + token_count - 1].line;

        let start_line_b = file_b.tokens[pos_b].line;
        let end_line_b = file_b.tokens[pos_b + token_count - 1].line;

        DuplicateBlockData {
            file_a: file_a.file_path.clone(),
            line_range_a: (start_line_a + 1, end_line_a + 1), // Convert to 1-based
            file_b: file_b.file_path.clone(),
            line_range_b: (start_line_b + 1, end_line_b + 1), // Convert to 1-based
            token_count,
            line_count: end_line_a - start_line_a + 1,
        }
    }

    /// 合併重疊的重複區塊
    fn merge_overlapping_blocks(mut blocks: Vec<DuplicateBlockData>) -> Vec<DuplicateBlockData> {
        if blocks.is_empty() {
            return blocks;
        }

        // 按檔案和起始行排序
        blocks.sort_by(|a, b| {
            a.file_a.cmp(&b.file_a)
                .then(a.line_range_a.0.cmp(&b.line_range_a.0))
                .then(a.file_b.cmp(&b.file_b))
                .then(a.line_range_b.0.cmp(&b.line_range_b.0))
        });

        let mut merged = Vec::new();
        let mut current = blocks[0].clone();

        for block in blocks.into_iter().skip(1) {
            // 檢查是否可以合併
            if Self::can_merge(&current, &block) {
                current = Self::merge_blocks(&current, &block);
            } else {
                merged.push(current);
                current = block;
            }
        }

        merged.push(current);
        merged
    }

    /// 檢查兩個區塊是否可以合併
    fn can_merge(a: &DuplicateBlockData, b: &DuplicateBlockData) -> bool {
        a.file_a == b.file_a
            && a.file_b == b.file_b
            && a.line_range_a.1 >= b.line_range_a.0.saturating_sub(1)
            && a.line_range_b.1 >= b.line_range_b.0.saturating_sub(1)
    }

    /// 合併兩個區塊
    fn merge_blocks(a: &DuplicateBlockData, b: &DuplicateBlockData) -> DuplicateBlockData {
        let new_range_a = (
            a.line_range_a.0.min(b.line_range_a.0),
            a.line_range_a.1.max(b.line_range_a.1),
        );
        let new_range_b = (
            a.line_range_b.0.min(b.line_range_b.0),
            a.line_range_b.1.max(b.line_range_b.1),
        );

        DuplicateBlockData {
            file_a: a.file_a.clone(),
            line_range_a: new_range_a,
            file_b: a.file_b.clone(),
            line_range_b: new_range_b,
            token_count: a.token_count + b.token_count,
            line_count: new_range_a.1 - new_range_a.0 + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_token_value() {
        assert_eq!(
            DuplicationDetector::normalize_token_value("identifier", "foo"),
            "$ID"
        );
        assert_eq!(
            DuplicationDetector::normalize_token_value("type_identifier", "String"),
            "$ID"
        );
        assert_eq!(
            DuplicationDetector::normalize_token_value("number", "42"),
            "$NUM"
        );
        assert_eq!(
            DuplicationDetector::normalize_token_value("integer_literal", "123"),
            "$NUM"
        );
        assert_eq!(
            DuplicationDetector::normalize_token_value("string_literal", "\"hello\""),
            "$STR"
        );
        assert_eq!(
            DuplicationDetector::normalize_token_value("punctuation", ";"),
            ";"
        );
    }

    #[test]
    fn test_detector_creation() {
        let detector = DuplicationDetector::new(50);
        assert_eq!(detector.min_tokens, 50);
        assert_eq!(detector.hash_base, 31);
        assert_eq!(detector.hash_modulus, (1u64 << 61) - 1);
    }

    #[test]
    fn test_empty_files() {
        let detector = DuplicationDetector::new(10);
        let files = vec![];
        let result = detector.detect(&files);

        assert_eq!(result.blocks.len(), 0);
        assert_eq!(result.total_duplicated_lines, 0);
        assert_eq!(result.duplication_percentage, 0.0);
    }

    #[test]
    fn test_can_merge_blocks() {
        let block_a = DuplicateBlockData {
            file_a: "file1.rs".to_string(),
            line_range_a: (10, 20),
            file_b: "file2.rs".to_string(),
            line_range_b: (15, 25),
            token_count: 50,
            line_count: 11,
        };

        let block_b = DuplicateBlockData {
            file_a: "file1.rs".to_string(),
            line_range_a: (19, 30),
            file_b: "file2.rs".to_string(),
            line_range_b: (24, 35),
            token_count: 60,
            line_count: 12,
        };

        assert!(DuplicationDetector::can_merge(&block_a, &block_b));

        let merged = DuplicationDetector::merge_blocks(&block_a, &block_b);
        assert_eq!(merged.line_range_a, (10, 30));
        assert_eq!(merged.line_range_b, (15, 35));
        assert_eq!(merged.token_count, 110);
    }

    #[test]
    fn test_modular_arithmetic() {
        let detector = DuplicationDetector::new(10);

        // Test add_mod
        assert_eq!(detector.add_mod(5, 10), 15);
        assert_eq!(detector.add_mod(detector.hash_modulus - 1, 2), 1);

        // Test mul_mod
        assert_eq!(detector.mul_mod(10, 20), 200);

        // Test sub_mod
        assert_eq!(detector.sub_mod(20, 5), 15);
        assert_eq!(detector.sub_mod(5, 10), detector.hash_modulus - 5);
    }
}
