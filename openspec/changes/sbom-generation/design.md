## Context

Atlas-Local 的 SCA 引擎（spec 008）已能解析 6 種生態系的鎖檔並產生 `Vec<Dependency>`。SBOM 產生是純序列化任務：將已解析的依賴資料轉換為 CycloneDX v1.5 或 SPDX v2.3 JSON 格式。漏洞資料庫可選——有則嵌入漏洞資訊，無則跳過。

既有架構：`atlas-sca` crate 提供 `Dependency`（name/version/ecosystem）、`Advisory`（CVE/CVSS）、`VulnDatabase`（SQLite 查詢），以及 `discover_lockfiles()` 和 `scan_dependencies()` API。

## Goals / Non-Goals

**Goals:**
- 產生符合 CycloneDX v1.5 JSON schema 的 SBOM 文件
- 產生符合 SPDX v2.3 JSON schema 的 SBOM 文件
- 為 6 種生態系產生正確的 Package URL (purl)
- 當漏洞資料庫可用時，在 CycloneDX 中嵌入已知漏洞
- 提供 `atlas sbom generate` CLI 介面，支援 stdout 和檔案輸出

**Non-Goals:**
- CycloneDX XML 或 SPDX tag-value 格式
- SBOM 簽署
- 授權條款（license）欄位填充
- VEX 文件產生
- SBOM 合併或比較

## Decisions

### D1: 模組放置 — 新增檔案至 `atlas-sca` crate

SBOM 產生直接複用 `atlas-sca` 的 `Dependency` 和 `Advisory` 型別。新增 4 個模組檔案而非獨立 crate，避免引入額外的 workspace 依賴。

- `purl.rs` — Package URL 產生器
- `sbom.rs` — SBOM 調度邏輯（接收依賴 + 漏洞，調用格式化器）
- `cyclonedx.rs` — CycloneDX v1.5 JSON 序列化
- `spdx.rs` — SPDX v2.3 JSON 序列化

**替代方案**: 獨立 `atlas-sbom` crate → 增加 workspace 複雜度，且 SBOM 功能緊密依賴 SCA 型別，分離收益不大。

### D2: 序列化策略 — 純 serde_json::Value 建構

使用 `serde_json::json!()` 巨集直接建構 JSON 結構，而非定義完整的 CycloneDX/SPDX Rust 型別。理由：

1. CycloneDX 和 SPDX 的 JSON schema 各有 50+ 欄位，定義完整型別的維護成本高
2. Atlas 只需寫出（不需解析）這些格式，單向序列化用 `json!()` 更直觀
3. 未來 schema 版本升級只需調整 JSON 建構，無需重構型別定義

**替代方案**: 完整 Rust struct + `#[derive(Serialize)]` → 型別安全但 200+ 行定義，維護成本不符效益。

### D3: purl 格式 — `pkg:{type}/{namespace}/{name}@{version}`

依 purl 規範，各生態系映射：

| Ecosystem | purl type | 範例 |
|-----------|-----------|------|
| npm | `npm` | `pkg:npm/lodash@4.17.21` |
| Cargo | `cargo` | `pkg:cargo/serde@1.0.0` |
| Maven | `maven` | `pkg:maven/org.apache/commons-lang3@3.12.0` |
| Go | `golang` | `pkg:golang/github.com/gin-gonic/gin@v1.9.0` |
| PyPI | `pypi` | `pkg:pypi/requests@2.31.0` |
| NuGet | `nuget` | `pkg:nuget/Newtonsoft.Json@13.0.3` |

Maven 的 `groupId:artifactId` 格式需特殊處理：purl namespace = groupId, name = artifactId。

### D4: 漏洞嵌入 — CycloneDX 專屬，SPDX 省略

CycloneDX v1.5 有原生 `vulnerabilities[]` 結構。SPDX v2.3 無對等結構（SPDX 3.0 才新增），因此僅在 CycloneDX 輸出中嵌入漏洞資訊。

### D5: CLI 介面 — `atlas sbom generate` 子命令

```
atlas sbom generate [OPTIONS] [TARGET]
  --format <FORMAT>    輸出格式：cyclonedx-json（預設）| spdx-json
  --output <PATH>      輸出檔案路徑（省略則寫入 stdout）
  --sca-db <PATH>      漏洞資料庫路徑（預設 ~/.atlas/vuln.db）
```

`TARGET` 預設為當前目錄。格式預設為 `cyclonedx-json`（業界最廣泛採用）。

### D6: SBOM 公開 API — `generate_sbom()` 函式

```rust
pub fn generate_sbom(
    scan_dir: &Path,
    format: SbomFormat,
    db: Option<&VulnDatabase>,
) -> Result<String, ScaError>
```

回傳 JSON 字串。CLI 負責寫入 stdout 或檔案。此 API 可被其他 crate（如未來的 Web Dashboard）直接呼叫。

### D7: 依賴樹結構 — flat list（無巢狀依賴）

目前鎖檔解析器回傳扁平化的 `Vec<Dependency>`，不含依賴關係圖。SBOM 的 `dependencies`（CycloneDX）和 `relationships`（SPDX）僅建立「根專案 → 所有依賴」的單層關係。未來可擴展為完整依賴樹。

## Risks / Trade-offs

- **R1: JSON schema 合規性** → 無自動化 schema 驗證。以手動比對 CycloneDX/SPDX 規範和單元測試涵蓋關鍵欄位結構來緩解。
- **R2: Maven purl namespace 解析** → `MavenParser` 目前將 `groupId:artifactId` 合併為 `name`。需在 purl 產生時正確分割。
- **R3: Go 模組路徑含 `/`** → Go purl 的 namespace 和 name 分割需特殊處理（如 `github.com/gin-gonic/gin` → namespace=`github.com/gin-gonic`, name=`gin`）。
- **R4: 欄位缺失風險** → 某些鎖檔不提供 download URL 或 license。使用 `NOASSERTION`（SPDX）或省略（CycloneDX）作為 fallback。
