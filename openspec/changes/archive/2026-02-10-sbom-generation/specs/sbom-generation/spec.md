# Capability: SBOM Generation

## Description

產生符合業界標準的軟體物料清單（SBOM），複用 SCA 引擎的鎖檔解析結果，輸出 CycloneDX v1.5 或 SPDX v2.3 JSON 格式。

## Requirements

### REQ-SB01: CLI 子命令

Atlas MUST 提供 `atlas sbom generate` 子命令。

**WHEN** 使用者執行 `atlas sbom generate`
**THEN** 系統偵測目標目錄中的鎖檔，解析依賴，產生 SBOM 文件

**WHEN** 使用者指定 `--format cyclonedx-json`
**THEN** 輸出 CycloneDX v1.5 JSON 格式

**WHEN** 使用者指定 `--format spdx-json`
**THEN** 輸出 SPDX v2.3 JSON 格式

**WHEN** 未指定 `--format`
**THEN** 預設使用 `cyclonedx-json`

### REQ-SB02: 輸出路徑

**WHEN** 使用者指定 `--output <path>`
**THEN** SBOM 寫入指定檔案路徑

**WHEN** 未指定 `--output`
**THEN** SBOM 寫入 stdout

### REQ-SB03: Package URL (purl)

每個依賴 MUST 產生符合 purl 規範的 Package URL。

**WHEN** 依賴為 npm 套件 `lodash@4.17.21`
**THEN** purl 為 `pkg:npm/lodash@4.17.21`

**WHEN** 依賴為 Maven 套件 `org.apache:commons-lang3@3.12.0`
**THEN** purl 為 `pkg:maven/org.apache/commons-lang3@3.12.0`

**WHEN** 依賴為 Go 模組 `github.com/gin-gonic/gin@v1.9.0`
**THEN** purl 為 `pkg:golang/github.com/gin-gonic/gin@v1.9.0`

**WHEN** 依賴為 Cargo 套件 `serde@1.0.0`
**THEN** purl 為 `pkg:cargo/serde@1.0.0`

**WHEN** 依賴為 PyPI 套件 `requests@2.31.0`
**THEN** purl 為 `pkg:pypi/requests@2.31.0`

**WHEN** 依賴為 NuGet 套件 `Newtonsoft.Json@13.0.3`
**THEN** purl 為 `pkg:nuget/Newtonsoft.Json@13.0.3`

### REQ-SB04: CycloneDX v1.5 格式

CycloneDX 輸出 MUST 符合 CycloneDX v1.5 JSON schema。

**WHEN** 產生 CycloneDX SBOM
**THEN** JSON 包含 `bomFormat: "CycloneDX"`, `specVersion: "1.5"`, `serialNumber` (UUID)

**WHEN** 有 N 個依賴
**THEN** `components[]` 包含 N 個元素，每個含 `type: "library"`, `name`, `version`, `purl`

**WHEN** 產生 CycloneDX SBOM
**THEN** `metadata` 包含 `timestamp`, `tools[]` (Atlas 工具資訊), `component` (根專案)

### REQ-SB05: CycloneDX 漏洞嵌入

**WHEN** 漏洞資料庫可用且含有匹配的 CVE
**THEN** CycloneDX 輸出包含 `vulnerabilities[]`，每個含 `id`, `source.name`, `ratings[].score`, `ratings[].severity`, `affects[].ref`

**WHEN** 漏洞資料庫不可用
**THEN** CycloneDX 輸出不含 `vulnerabilities` 欄位，log 記錄 "Vulnerability database not found"

### REQ-SB06: SPDX v2.3 格式

SPDX 輸出 MUST 符合 SPDX v2.3 JSON schema。

**WHEN** 產生 SPDX SBOM
**THEN** JSON 包含 `spdxVersion: "SPDX-2.3"`, `dataLicense: "CC0-1.0"`, `SPDXID: "SPDXRef-DOCUMENT"`

**WHEN** 有 N 個依賴
**THEN** `packages[]` 包含 N+1 個元素（根專案 + N 個依賴），每個含 `SPDXID`, `name`, `versionInfo`, `downloadLocation`

**WHEN** 依賴有 purl
**THEN** `externalRefs[]` 包含 `referenceType: "purl"`, `referenceLocator: "<purl>"`

### REQ-SB07: SPDX 關係

**WHEN** 產生 SPDX SBOM
**THEN** `relationships[]` 包含從根專案到每個依賴的 `DEPENDS_ON` 關係

**WHEN** 產生 SPDX SBOM
**THEN** `creationInfo` 包含 `created` (ISO 8601), `creators[]` 含 `Tool: atlas-local`

### REQ-SB08: 空依賴處理

**WHEN** 目標目錄中無鎖檔
**THEN** 產生含零 components 的 SBOM，stderr 輸出警告 "No lockfiles found"

**WHEN** 鎖檔存在但解析失敗
**THEN** 跳過該鎖檔並 log warning，繼續處理其他鎖檔

### REQ-SB09: 效能

**WHEN** 專案含 500 個依賴
**THEN** SBOM 產生在 2 秒內完成

### REQ-SB10: 公開 API

`atlas-sca` crate MUST 提供 `generate_sbom()` 公開函式。

**WHEN** 呼叫 `generate_sbom(scan_dir, format, db)`
**THEN** 回傳 `Result<String, ScaError>`，String 為完整的 JSON SBOM 文件

### REQ-SB11: 重複依賴

**WHEN** 同一套件出現在多個鎖檔中（同版本）
**THEN** SBOM 中只列出一次（依 name+version+ecosystem 去重）

**WHEN** 同一套件名稱出現在不同生態系
**THEN** 分別列出，以 purl 區分

### REQ-SB12: SPDX Document Namespace

**WHEN** 產生 SPDX SBOM
**THEN** `documentNamespace` 使用格式 `https://atlas.local/spdx/{project-name}/{uuid}`

### REQ-SB13: SPDX Download Location

**WHEN** 依賴無已知下載位置
**THEN** `downloadLocation` 設為 `NOASSERTION`

### REQ-SB14: CycloneDX Dependencies

**WHEN** 產生 CycloneDX SBOM
**THEN** `dependencies[]` 包含根專案 ref 指向所有 component refs 的 flat 結構

### REQ-SB15: 漏洞資料庫路徑

**WHEN** 使用者指定 `--sca-db <path>`
**THEN** 使用指定路徑的漏洞資料庫

**WHEN** 未指定 `--sca-db`
**THEN** 預設使用 `~/.atlas/vuln.db`
