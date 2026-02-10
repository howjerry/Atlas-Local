## 1. Package URL (purl) 產生器

- [x] 1.1 建立 `crates/atlas-sca/src/purl.rs` 模組，實作 `dependency_to_purl(dep: &Dependency) -> String`
- [x] 1.2 實作 npm purl：`pkg:npm/{name}@{version}`
- [x] 1.3 實作 Cargo purl：`pkg:cargo/{name}@{version}`
- [x] 1.4 實作 Maven purl：分割 `groupId:artifactId` → `pkg:maven/{groupId}/{artifactId}@{version}`
- [x] 1.5 實作 Go purl：`pkg:golang/{module_path}@{version}`
- [x] 1.6 實作 PyPI purl：`pkg:pypi/{name}@{version}`（名稱小寫化）
- [x] 1.7 實作 NuGet purl：`pkg:nuget/{name}@{version}`
- [x] 1.8 purl 單元測試：6 種生態系各至少 2 個案例（含 scoped npm、Maven groupId、Go 長路徑）

## 2. SBOM 核心邏輯

- [x] 2.1 建立 `crates/atlas-sca/src/sbom.rs` 模組，定義 `SbomFormat` enum（CycloneDxJson, SpdxJson）
- [x] 2.2 實作 `generate_sbom(scan_dir, format, db) -> Result<String, ScaError>` 公開 API
- [x] 2.3 內部流程：discover_lockfiles → parse → dedup by (name, version, ecosystem) → 呼叫格式化器
- [x] 2.4 漏洞資料庫可選：`Option<&VulnDatabase>`，無則跳過漏洞嵌入
- [x] 2.5 空依賴處理：無鎖檔時 log warning 並回傳含零 components 的 SBOM
- [x] 2.6 在 `lib.rs` 中 `pub mod sbom;` + `pub mod purl;` + `pub mod cyclonedx;` + `pub mod spdx;`

## 3. CycloneDX v1.5 序列化

- [x] 3.1 建立 `crates/atlas-sca/src/cyclonedx.rs` 模組
- [x] 3.2 實作 `format_cyclonedx(deps, vulns, project_name) -> String`
- [x] 3.3 頂層結構：`bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `serialNumber` (UUID v4)
- [x] 3.4 `metadata` 區塊：`timestamp` (ISO 8601)、`tools[{ name: "atlas-local", version }]`、`component` (根專案)
- [x] 3.5 `components[]`：每個依賴 → `{ type: "library", name, version, purl, bom-ref }`
- [x] 3.6 `vulnerabilities[]`：每個匹配的 CVE → `{ id, source: { name: "NVD" }, ratings[{ score, severity }], affects[{ ref }] }`
- [x] 3.7 `dependencies[]`：根專案 ref → 所有 component refs 的 flat 結構
- [x] 3.8 CycloneDX 單元測試：驗證 JSON 結構、欄位完整性、無漏洞時省略 vulnerabilities、空依賴

## 4. SPDX v2.3 序列化

- [x] 4.1 建立 `crates/atlas-sca/src/spdx.rs` 模組
- [x] 4.2 實作 `format_spdx(deps, project_name) -> String`
- [x] 4.3 頂層結構：`spdxVersion: "SPDX-2.3"`, `dataLicense: "CC0-1.0"`, `SPDXID: "SPDXRef-DOCUMENT"`, `documentNamespace`
- [x] 4.4 `creationInfo`：`created` (ISO 8601)、`creators: ["Tool: atlas-local"]`
- [x] 4.5 根專案 package：`SPDXRef-RootPackage`, `name`, `versionInfo: ""`，`downloadLocation: NOASSERTION`
- [x] 4.6 依賴 packages：每個 → `{ SPDXID: "SPDXRef-Package-{idx}", name, versionInfo, downloadLocation: "NOASSERTION", externalRefs[{ referenceType: "purl", referenceLocator }] }`
- [x] 4.7 `relationships[]`：根專案 → 每個依賴的 `DEPENDS_ON` 關係 + `DOCUMENT DESCRIBES RootPackage`
- [x] 4.8 SPDX 單元測試：驗證 JSON 結構、欄位完整性、relationships 數量、NOASSERTION 預設值

## 5. CLI 整合

- [x] 5.1 建立 `crates/atlas-cli/src/commands/sbom.rs`：`SbomArgs` + `SbomCommand::Generate`
- [x] 5.2 實作 `--format` 旗標：接受 `cyclonedx-json`（預設）和 `spdx-json`
- [x] 5.3 實作 `--output` 旗標：指定輸出路徑，省略則 stdout
- [x] 5.4 實作 `--sca-db` 旗標：漏洞資料庫路徑（預設 `~/.atlas/vuln.db`）
- [x] 5.5 實作 `[TARGET]` 位置參數：掃描目標目錄（預設 `.`）
- [x] 5.6 在 `commands/mod.rs` 新增 `pub mod sbom;`
- [x] 5.7 在 `main.rs` 註冊 `Sbom(commands::sbom::SbomArgs)` 子命令
- [x] 5.8 CLI 整合測試：cyclonedx 格式、spdx 格式、stdout 輸出、檔案輸出

## 6. 依賴去重

- [x] 6.1 在 `sbom.rs` 中實作依賴去重：相同 (name, version, ecosystem) 只保留一次
- [x] 6.2 不同生態系的同名套件分別保留
- [x] 6.3 去重單元測試

## 7. 測試與迴歸

- [x] 7.1 端對端測試：建立含多生態系鎖檔的測試專案，驗證 CycloneDX 輸出結構
- [x] 7.2 端對端測試：同上，驗證 SPDX 輸出結構
- [x] 7.3 端對端測試：含漏洞資料庫時 CycloneDX vulnerabilities 正確嵌入
- [x] 7.4 效能測試：500 依賴的 SBOM 產生在 2 秒內完成
- [x] 7.5 迴歸測試：確認所有既有測試通過（SCA + CLI + 全 workspace）
