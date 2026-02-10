## 1. Workspace 基礎建設

- [x] 1.1 建立 `crates/atlas-sca/` crate 骨架（Cargo.toml + lib.rs），加入 workspace members
- [x] 1.2 新增 `Category::Sca` variant 至 `atlas-rules` Category enum
- [x] 1.3 更新所有 `match Category` 分支（gate.rs、report 模組、engine.rs 等），確保編譯通過
- [x] 1.4 新增 `Ecosystem` enum（npm, cargo, maven, go, pypi, nuget）和 `Dependency` struct 至 `atlas-sca`
- [x] 1.5 定義 `LockfileParser` trait：`fn parse(content: &str) -> Result<Vec<Dependency>>`

## 2. 鎖檔解析器

- [x] 2.1 實作 npm 解析器：解析 `package-lock.json` v2/v3 格式，提取依賴名稱和版本
- [x] 2.2 npm 解析器單元測試：v2 格式、v3 格式、畸形 JSON 錯誤處理
- [x] 2.3 實作 Cargo 解析器：解析 `Cargo.lock` TOML 格式
- [x] 2.4 Cargo 解析器單元測試：正常解析、畸形 TOML 錯誤處理
- [x] 2.5 實作 Maven 解析器：解析 `pom.xml`（XML dependency 元素）和 `gradle.lockfile`
- [x] 2.6 Maven 解析器單元測試：pom.xml、gradle.lockfile、groupId:artifactId 格式
- [x] 2.7 實作 Go 解析器：解析 `go.sum`，去重 h1/go.mod 條目，strip v prefix
- [x] 2.8 Go 解析器單元測試：正常解析、去重、v prefix 處理
- [x] 2.9 實作 Python 解析器：解析 `requirements.txt`（==、>= 版本）和 `Pipfile.lock`（JSON）
- [x] 2.10 Python 解析器單元測試：pinned 版本、range 版本、Pipfile.lock default/develop sections
- [x] 2.11 實作 NuGet 解析器：解析 `packages.lock.json`（resolved 版本）
- [x] 2.12 NuGet 解析器單元測試
- [x] 2.13 實作鎖檔自動偵測邏輯：根據檔名判斷解析器，支援遞迴目錄探索

## 3. 漏洞資料庫

- [x] 3.1 實作 `database.rs`：VulnDatabase struct（open、create_tables、query、metadata）
- [x] 3.2 定義 SQLite schema（advisories 表 + idx_ecosystem_package 索引）
- [x] 3.3 實作 `query_advisories(ecosystem, package_name) -> Vec<Advisory>` 查詢方法
- [x] 3.4 實作批次查詢：`query_batch(deps: &[Dependency]) -> HashMap<DependencyKey, Vec<Advisory>>`
- [x] 3.5 實作資料庫 metadata 查詢（advisory_count、last_updated）
- [x] 3.6 實作 30 天過期警告邏輯（VulnDatabase::is_stale + scan pipeline 30 天警告）
- [x] 3.7 VulnDatabase 單元測試：建立測試資料庫、插入 advisory、查詢匹配、空資料庫處理

## 4. 版本匹配引擎

- [x] 4.1 實作 `matcher.rs`：`VersionMatcher` trait 和 `matches(version: &str, affected_range: &str, ecosystem: Ecosystem) -> bool`
- [x] 4.2 實作 semver 匹配（npm/Cargo/NuGet）：使用 `semver` crate 的 `VersionReq::matches`
- [x] 4.3 實作 Go 版本匹配：semver + v prefix 處理
- [x] 4.4 實作 Maven 版本比較器：major.minor.patch.qualifier 排序
- [x] 4.5 實作 PyPI (PEP 440) 版本比較器：epoch、pre/post/dev release
- [x] 4.6 版本匹配單元測試語料庫：每個生態系至少 10 個邊界案例

## 5. SCA Finding 產生

- [x] 5.1 實作 CVSS → Severity 映射函式（Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, null → Medium）
- [x] 5.2 實作 `create_sca_finding()`: 建構 Finding（rule_id `atlas/sca/{ecosystem}/{cve_id}`, category Sca, metadata 欄位）
- [x] 5.3 實作 `scan_dependencies()` 公開 API：鎖檔解析 → 資料庫查詢 → 版本匹配 → Finding 產生
- [x] 5.4 SCA finding 單元測試：metadata 完整性、severity 映射、無 CVSS 預設值

## 6. 資料庫更新機制

- [x] 6.1 實作 `update.rs`：bundle 格式定義（vuln.db + 簽章 metadata）
- [x] 6.2 實作 Ed25519 簽章驗證（複用 rulepack 的 ed25519-dalek 模式）
- [x] 6.3 實作原子替換邏輯（write temp → rename）
- [x] 6.4 update-db 單元測試：有效簽章接受、無效簽章拒絕、原子替換

## 7. Scan Pipeline 整合

- [x] 7.1 在 scan 指令的 `execute()` 中新增 SCA 階段：偵測 VulnDatabase 並呼叫 `scan_dependencies()`
- [x] 7.2 傳入 VulnDatabase 實例，呼叫 `scan_dependencies()`，合併 findings
- [x] 7.3 處理資料庫不存在的情況：跳過 SCA 並 log warning
- [x] 7.4 新增 `--no-sca` 旗標和 `--sca-db` 路徑選項
- [x] 7.5 Pipeline 整合測試：既有 SAST 測試全部通過（SCA 無副作用）

## 8. CLI 整合

- [x] 8.1 新增 `atlas sca update-db <path>` 子指令（clap command registration）
- [x] 8.2 實作 update-db 指令邏輯：讀取 bundle → 驗證簽章 → 替換資料庫 → 顯示結果
- [x] 8.3 新增 `atlas sca status` 子指令（顯示資料庫狀態）
- [x] 8.4 在 scan 指令中加入 `--no-sca` 旗標（停用 SCA 掃描）

## 9. Gate/Policy 整合

- [x] 9.1 確認 `category_overrides.sca` 在 gate 評估中正確運作
- [x] 9.2 Gate 單元測試：SCA category override、global threshold fallback（85 tests pass）

## 10. Report 整合

- [x] 10.1 確認 SCA findings 在 JSON 報告中正確序列化（category: "sca" + metadata 欄位）
- [x] 10.2 確認 SCA findings 在 SARIF 報告中正確輸出（ruleId prefix `atlas/sca/`）
- [x] 10.3 確認 SCA findings 在 JSONL 報告中正確輸出
- [x] 10.4 Report 序列化使用統一的 Finding struct，SCA findings 自動包含所有格式

## 11. 測試 Fixtures 與迴歸

- [x] 11.1 每個生態系均有解析器單元測試 fixtures（正常 + 畸形輸入）
- [x] 11.2 VulnDatabase 測試中建立臨時 SQLite 資料庫並插入測試 CVE 條目
- [x] 11.3 端對端測試：掃描含已知漏洞依賴的專案，驗證完整管線（鎖檔 → 資料庫 → finding → gate → report）
- [x] 11.4 迴歸測試：確認所有既有 SAST 測試通過（841 tests, 0 failed）
- [x] 11.5 效能測試：500 依賴的 SCA 掃描在 3 秒內完成
