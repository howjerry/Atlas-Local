## Why

軟體物料清單（SBOM）已成為法規遵循的必要產出（US EO 14028、EU Cyber Resilience Act）。Atlas-Local 的 SCA 引擎（spec 008）已具備鎖檔解析和依賴識別能力，但缺少標準化的 SBOM 輸出。新增 CycloneDX v1.5 和 SPDX v2.3 JSON 格式產生功能，可直接複用既有的依賴解析結果，無需額外掃描。

## What Changes

- 新增 `atlas sbom generate` CLI 子命令，支援 `--format cyclonedx-json|spdx-json` 和 `--output` 選項
- 實作 CycloneDX v1.5 JSON 序列化：components（type/name/version/purl）、metadata（tool/timestamp）、vulnerabilities（當資料庫可用時）
- 實作 SPDX v2.3 JSON 序列化：packages（SPDXID/name/versionInfo/externalRefs）、documentCreation、relationships（DEPENDS_ON）
- 實作 Package URL (purl) 產生器：支援 npm/cargo/maven/golang/pypi/nuget 6 種生態系
- 複用 `atlas-sca` 的 LockfileParser + VulnDatabase，純序列化任務

## Capabilities

### New Capabilities
- `sbom-generation`: SBOM 文件產生引擎 — CycloneDX v1.5 和 SPDX v2.3 JSON 格式，含 purl 映射和漏洞關聯

### Modified Capabilities
（無需修改既有 capability 的 spec 層級行為）

## Impact

- **新增檔案**: `crates/atlas-sca/src/sbom.rs`（調度）、`cyclonedx.rs`（CycloneDX 序列化）、`spdx.rs`（SPDX 序列化）、`purl.rs`（purl 產生）、`crates/atlas-cli/src/commands/sbom.rs`（CLI）
- **修改檔案**: `crates/atlas-cli/src/main.rs`（註冊 sbom 子命令）、`crates/atlas-cli/src/commands/mod.rs`
- **依賴**: 複用 `atlas-sca` 的 Dependency/Advisory/VulnDatabase，無新外部依賴（純 serde_json 序列化）
- **風險**: 低 — 純產出功能，不影響既有掃描管線
