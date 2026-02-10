## Context

Atlas-Local 是一個 Rust workspace，包含 `atlas-cli`、`atlas-core`、`atlas-analysis`、`atlas-rules`、`atlas-policy`、`atlas-report` 等 crate。現有掃描管線流程為：檔案探索 → AST 解析 → L1/L2 規則評估 → Finding 產生 → Gate 評估 → Report 輸出。

Finding 結構已有 `category: Category` 欄位（目前支援 `Security`、`Quality`、`Secrets`、`Metrics`），並透過 `GateFinding` trait 參與 gate 評估。Report 模組支援 JSON/SARIF/JSONL 三種格式。

SCA 需要在此管線中新增一個**獨立於 AST 分析的鎖檔掃描階段**，產生與 SAST findings 同構的 `Finding`，無縫參與後續 gate/report 流程。

## Goals / Non-Goals

**Goals:**

- 新增 `atlas-sca` crate 作為獨立模組，職責涵蓋鎖檔解析、漏洞資料庫查詢、版本匹配
- 支援 6 個生態系的鎖檔格式（npm、Cargo、Maven/Gradle、Go、Python、NuGet）
- 離線 SQLite 漏洞資料庫，Ed25519 簽章更新機制
- SCA findings 融入既有 Finding/Gate/Report 管線，無需修改下游消費端
- `atlas sca update-db` CLI 子指令

**Non-Goals:**

- 遞移依賴解析（僅解析鎖檔中的直接條目）
- 原始碼可達性分析（不判斷漏洞程式碼路徑是否實際被呼叫）
- 即時 NVD/OSV API 查詢（完全離線）
- License 合規掃描（留給 SBOM spec）
- 私有 registry 支援
- 自動升級建議

## Decisions

### D1: 新增 `Category::Sca` 而非重用 `Category::Security`

**選擇**: 新增 `Category::Sca` variant

**理由**: SCA findings 的本質（已知 CVE vs 程式碼模式匹配）與 SAST security findings 不同，團隊通常需要獨立的 gate 閾值。使用獨立 category 允許 `category_overrides.sca` 策略配置，不會干擾現有 security 閾值。

**替代方案**: 重用 `Category::Security` 並用 metadata 區分 — 但這會讓 gate 無法獨立控制 SCA 閾值。

### D2: SCA 在 scan pipeline 中作為後置階段

**選擇**: 在 `ScanEngine::scan_with_options` 中，SAST 分析完成後執行 SCA 掃描，合併 findings

```
檔案探索 → SAST (L1/L2) → SCA (鎖檔偵測+查詢) → 合併 findings → Gate → Report
```

**理由**: SCA 不需要 AST 解析，與 SAST 完全正交。放在 SAST 後可複用已探索的檔案列表來偵測鎖檔，且不影響現有 SAST 效能。

**替代方案**: 獨立 CLI 子指令 `atlas sca scan` — 但這會導致用戶需執行兩次掃描，無法在單次 `atlas scan` 中得到完整結果。

### D3: 離線 SQLite 漏洞資料庫

**選擇**: SQLite 單檔案資料庫，存放於 `~/.atlas/vuln.db`

**理由**:
- 完全離線，適合 CI/CD 和氣隙環境
- SQLite 查詢效能優秀（500 個依賴 < 100ms）
- `rusqlite` 已是 workspace 依賴（用於 `atlas-cache`）
- 單檔案便於分發和備份

**替代方案**:
- 嵌入式 JSON/bincode — 缺乏索引，大量 advisory 時查詢慢
- 連線 API (OSV/NVD) — 需要網路，不適合離線場景

**Schema**:

```sql
CREATE TABLE advisories (
    id TEXT PRIMARY KEY,         -- CVE ID (e.g., "CVE-2021-23337")
    ecosystem TEXT NOT NULL,     -- "npm", "cargo", "maven", "go", "pypi", "nuget"
    package_name TEXT NOT NULL,
    affected_range TEXT NOT NULL, -- semver range (e.g., "< 4.17.21")
    fixed_version TEXT,          -- nullable: 可能無修復版本
    cvss_score REAL,             -- CVSS v3 score (0.0-10.0)
    severity TEXT NOT NULL,      -- "critical", "high", "medium", "low"
    description TEXT NOT NULL,
    advisory_url TEXT,
    published_at TEXT             -- ISO 8601
);

CREATE INDEX idx_ecosystem_package ON advisories (ecosystem, package_name);
```

### D4: Ed25519 簽章驗證機制

**選擇**: 複用 `atlas-rules` 中 rulepack 的 Ed25519 簽章模式

**理由**: `ed25519-dalek` 已是 workspace 依賴，rulepack 的 manifest 簽章流程（JSON 序列化 → SHA-256 → Ed25519 簽署）可直接套用於資料庫 bundle。

**Bundle 格式**: 將 `vuln.db` + 簽章 metadata 打包為單一檔案，`atlas sca update-db` 先驗證簽章再替換。

### D5: 版本匹配策略

**選擇**: 根據生態系使用不同的版本比較邏輯

| 生態系 | 版本格式 | 比較策略 |
|--------|----------|----------|
| npm, Cargo, NuGet | semver | `semver` crate 的 `VersionReq::matches` |
| Maven | Maven versioning | 自訂比較器（major.minor.patch.qualifier） |
| Go | Go module versioning | semver + `v` prefix 處理 |
| PyPI | PEP 440 | 自訂比較器（epoch, pre/post/dev releases） |

**理由**: 不同生態系的版本語意不同，強制統一會產生誤報。

### D6: SCA Finding 的 `line_range` 處理

**選擇**: 定位到鎖檔中該依賴的實際行號（如可偵測），否則使用 `LineRange::new(1, 0, 1, 0)`

**理由**: npm `package-lock.json` 和 `Cargo.lock` 是結構化格式，可透過解析定位依賴在檔案中的位置。這讓 IDE 整合和 SARIF 報告更精確。對於無法定位的格式（如 `requirements.txt` 的行是明確的，但 `go.sum` 每行一條），盡量提供行號。

### D7: `atlas-sca` Crate 結構

```
crates/atlas-sca/
├── Cargo.toml
└── src/
    ├── lib.rs              -- 公開 API: scan_dependencies()
    ├── lockfile/
    │   ├── mod.rs           -- LockfileParser trait + 自動偵測
    │   ├── npm.rs           -- package-lock.json (v2/v3)
    │   ├── cargo.rs         -- Cargo.lock
    │   ├── maven.rs         -- pom.xml + gradle.lockfile
    │   ├── go.rs            -- go.sum
    │   ├── python.rs        -- requirements.txt + Pipfile.lock
    │   └── nuget.rs         -- packages.lock.json
    ├── database.rs          -- VulnDatabase: open/query/update
    ├── matcher.rs           -- 版本比較邏輯 (semver + 自訂)
    └── update.rs            -- update-db 指令: 下載/驗證/替換
```

## Risks / Trade-offs

**[R1] 漏洞資料庫時效性** → 使用者需定期執行 `atlas sca update-db`。首次安裝時 bundled 資料庫可能已過時。Mitigation: 掃描結果顯示資料庫最後更新時間，超過 30 天顯示警告。

**[R2] 版本比較正確性** → Maven 和 PyPI 的版本語意複雜（qualifier、epoch、pre-release），自訂比較器可能有邊界情況。Mitigation: 建立涵蓋各生態系的版本比較測試語料庫（至少 20 個邊界案例/生態系）。

**[R3] Category::Sca 破壞性變更** → 新增 enum variant 需要更新所有 `match` 表達式。Mitigation: Category enum 已有 4 個 variant，`match` 分支明確且有限（gate.rs、report 模組），影響可控。

**[R4] 大型鎖檔效能** → monorepo 的 `package-lock.json` 可能有數千個依賴。Mitigation: 鎖檔解析使用串流式 JSON 解析（`serde_json::from_reader`），資料庫查詢使用批次 `IN` 子句而非逐一查詢。

**[R5] 無 bundled 資料庫的首次體驗** → 嵌入完整資料庫（~50-100 MB）會大幅增加二進位大小。Mitigation: 首次掃描若無資料庫，產生 info-level finding 提示執行 `atlas sca update-db`，不阻擋掃描流程。
