# Atlas Local

高效能、離線優先的靜態應用安全測試（SAST）工具，以 Rust 打造。Atlas 使用 tree-sitter AST 解析，結合宣告式 YAML 規則與多層分析引擎，掃描原始碼中的安全漏洞、機密洩漏與程式碼品質問題。同時整合軟體組成分析（SCA）與 SBOM 產生，為企業 CI/CD 環境提供完整的安全掃描方案。

## 功能特色

### 掃描引擎

- **9 種語言支援** — TypeScript/JavaScript、Java、Python、Go、C#、Kotlin、PHP、Ruby
- **204+ 條內建規則** — 76 安全、113 品質、15 機密偵測
- **三層分析深度** — L1 模式匹配、L2 程序內資料流分析、L3 跨程序污點追蹤
- **程式碼品質度量** — Cyclomatic/Cognitive complexity、程式碼重複偵測、LOC 統計
- **Diff-Aware 掃描** — 僅分析 git diff 變更的檔案，大幅縮短 CI 掃描時間

### 軟體組成分析（SCA）

- **6 個生態系** — npm、Cargo、Maven/Gradle、Go、Python（pip/Pipfile）、NuGet
- **離線漏洞資料庫** — SQLite 儲存，Ed25519 簽章驗證更新
- **CVE/CVSS 中繼資料** — 自動比對已知漏洞並產生 SCA findings

### SBOM 產生

- **CycloneDX v1.5** — 含漏洞資訊嵌入
- **SPDX v2.3** — ISO/IEC 5962:2021 標準格式

### 合規框架

- **OWASP Top 10 2021**、**PCI DSS 4.0**、**NIST 800-53**、**HIPAA Security**
- 規則對應覆蓋率報告

### 企業功能

- **Policy-as-Code** — YAML 定義嚴重度門檻，掃描失敗返回非零 exit code
- **Baseline 管理** — 增量採用，避免警報疲勞
- **結果快取** — SQLite 快取，跳過未變更檔案
- **Rulepack 簽章** — Ed25519 簽署的規則包分發
- **稽核 Bundle** — 產生簽署的合規稽核包
- **多格式報告** — JSON（Atlas Findings v1.0.0）、SARIF v2.1.0、JSONL
- **平行掃描** — Rayon 多執行緒檔案處理
- **離線運作** — 完全不需網路連線，適合 air-gapped 環境

## 快速開始

### 建置

```bash
cargo build --release
```

### 掃描專案

```bash
# JSON 輸出至 stdout
atlas scan ~/Projects/MyApp

# 多格式報告輸出至目錄
atlas scan ~/Projects/MyApp --format json,sarif --output reports/
# -> reports/MyApp/20260208-220854/atlas-report.json
# -> reports/MyApp/20260208-220854/atlas-report.sarif

# 單一檔案輸出
atlas scan ~/Projects/MyApp --format json --output result.json

# 指定語言
atlas scan ~/Projects/MyApp --lang typescript,python

# 搭配 Policy 門檻
atlas scan ~/Projects/MyApp --policy policy.yaml

# Diff-Aware 掃描（僅掃描變更檔案）
atlas scan ~/Projects/MyApp --diff origin/main

# 啟用 L2 資料流分析 + 品質度量
atlas scan ~/Projects/MyApp --analysis-level L2 --metrics

# SCA 依賴漏洞掃描（預設啟用，可停用）
atlas scan ~/Projects/MyApp --no-sca
```

### Exit Codes

| Code | 意義                             |
| ---- | -------------------------------- |
| 0    | 掃描完成，所有 policy gates 通過 |
| 1    | 一或多個 policy gates 失敗       |
| 2    | 引擎錯誤                         |
| 3    | 授權驗證失敗                     |
| 4    | 設定錯誤                         |

## CLI 參考

```
atlas <COMMAND>

Commands:
  scan         掃描專案的安全漏洞
  config       顯示/驗證 Atlas 設定
  rulepack     管理簽署的規則包（install, list, rollback）
  baseline     管理 baseline 增量採用（create, diff）
  license      管理 Atlas 授權（activate, status, deactivate）
  compliance   合規框架覆蓋率報告
  audit        產生簽署的稽核 bundle
  sca          SCA 漏洞資料庫管理（update-db, status）
  sbom         產生 SBOM（generate）
  diag         顯示診斷資訊
```

### `atlas scan`

```
atlas scan <TARGET> [OPTIONS]

Options:
  --format <FORMAT>          輸出格式：json, sarif, jsonl（逗號分隔）[預設: json]
  -o, --output <PATH>        輸出目錄或檔案路徑
  --policy <FILE>            Policy 檔案
  --baseline <FILE>          Baseline 檔案
  --lang <LANGUAGES>         掃描語言（逗號分隔）
  --analysis-level <LEVEL>   分析深度：L1（預設）或 L2
  --diff <GIT-REF>           Diff-Aware 掃描的 git 參考
  --diff-gate-mode <MODE>    Diff gate 模式：all（預設）或 new-only
  --metrics                  啟用品質度量計算
  --min-confidence <LEVEL>   最低信心等級過濾
  --no-sca                   停用 SCA 依賴掃描
  --sca-db <PATH>            SCA 漏洞資料庫路徑
  -j, --jobs <N>             平行工作數
  --no-cache                 停用結果快取
  --no-report                停用自動報告儲存
  -v, --verbose              詳細輸出
  -q, --quiet                靜默模式
  --timestamp                輸出包含時間戳記
```

**輸出路徑行為：**

| `--output` 值         | 行為                                               |
| --------------------- | -------------------------------------------------- |
| _（省略）_            | stdout                                             |
| `reports/`（目錄）    | `reports/{project}/{timestamp}/atlas-report.{ext}` |
| `result.json`（檔案） | 直接寫入該檔案                                     |

### `atlas sca`

```
atlas sca update-db --bundle <PATH>   從簽署的 bundle 更新漏洞資料庫
atlas sca status                      顯示漏洞資料庫狀態
```

### `atlas sbom`

```
atlas sbom generate [TARGET] [OPTIONS]

Options:
  --format <FORMAT>    輸出格式：cyclonedx-json（預設）或 spdx-json
  --output <PATH>      輸出檔案路徑（省略則輸出至 stdout）
  --sca-db <PATH>      SCA 漏洞資料庫路徑（CycloneDX 嵌入漏洞資訊）
```

### `atlas compliance`

```
atlas compliance coverage <FRAMEWORK_IDS...> [OPTIONS]

Options:
  --format <FORMAT>    輸出格式：table（預設）或 json
```

## 內建規則

| 語言          | 安全   | 品質    | 合計    |
| ------------- | ------ | ------- | ------- |
| TypeScript/JS | 12     | 18      | 30      |
| Java          | 10     | 14      | 24      |
| Python        | 10     | 15      | 25      |
| Go            | 8      | 12      | 20      |
| C#            | 8      | 12      | 20      |
| Kotlin        | 8      | 12      | 20      |
| PHP           | 10     | 15      | 25      |
| Ruby          | 10     | 15      | 25      |
| Secrets       | 15     | —       | 15      |
| **合計**      | **91** | **113** | **204** |

### 安全規則

SQL injection、command injection、path traversal、insecure deserialization、XSS、eval usage、hardcoded credentials、weak cryptography、SSRF、XXE 等。

### 品質規則

Empty catch blocks、TODO comments、console/debug logging 殘留、type assertion 濫用、bare exception handling、unused imports、magic numbers 等。

### 機密偵測

API keys、private keys、AWS credentials、GitHub tokens、JWT secrets、Slack webhooks、Azure storage keys、NPM tokens、Google API keys、connection string passwords、高熵字串等。

## 設定

### `.atlas.yaml`

放置於專案根目錄或家目錄：

```yaml
scan:
  languages: [typescript, javascript, java, python, go, csharp, kotlin, php, ruby]
  exclude_patterns:
    - "node_modules/**"
    - "vendor/**"
    - "dist/**"
  max_file_size_kb: 1024

cache:
  enabled: true
  max_size_mb: 500

reporting:
  default_format: json
```

### `.atlasignore`

遵循 `.gitignore` 語法排除掃描檔案：

```gitignore
tests/fixtures/
target/
dist/
vendor/
node_modules/
*.min.js
```

### Policy 檔案

定義 gate 門檻，超過時掃描失敗或警告：

```yaml
schema_version: "1.0.0"
name: my-project-policy
fail_on:
  critical: 0
  high: 5
warn_on:
  medium: 10
suppressions:
  - fingerprint: "abc123..."
    reason: "Accepted risk"
    expires: "2026-12-31"
```

## 專案結構

```
Atlas-Local/
├── crates/
│   ├── atlas-cli/          # CLI 入口（binary）
│   ├── atlas-core/         # 掃描引擎協調
│   ├── atlas-lang/         # Tree-sitter 語言適配器
│   ├── atlas-rules/        # 規則載入與 rulepack 管理
│   ├── atlas-analysis/     # L1/L2/L3 分析引擎、度量、重複偵測
│   ├── atlas-sca/          # 軟體組成分析（SCA）、SBOM 產生
│   ├── atlas-policy/       # Policy gating 與 baseline
│   ├── atlas-report/       # JSON、SARIF、JSONL 格式化
│   ├── atlas-license/      # Node-locked 授權驗證
│   ├── atlas-audit/        # 稽核 bundle 產生
│   └── atlas-cache/        # SQLite 結果快取
├── rules/
│   ├── builtin/            # 204 條 L1 YAML 規則定義
│   │   ├── typescript/     # 30 rules
│   │   ├── java/           # 24 rules
│   │   ├── python/         # 25 rules
│   │   ├── go/             # 20 rules
│   │   ├── csharp/         # 20 rules
│   │   ├── kotlin/         # 20 rules
│   │   ├── php/            # 25 rules
│   │   ├── ruby/           # 25 rules
│   │   └── secrets/        # 15 rules
│   ├── l2/                 # L2 資料流分析規則
│   ├── l3/                 # L3 跨程序污點追蹤規則
│   └── compliance/         # 合規框架對應定義
├── tests/
│   ├── fixtures/           # 測試用漏洞程式碼範例
│   └── integration/        # 整合測試
└── specs/                  # 功能規格書
```

## 開發

### 前置需求

- Rust stable toolchain（2024 edition, 1.85+）
- C compiler（tree-sitter grammar 編譯用）

### 指令

```bash
cargo build                    # Debug 建置
cargo build --release          # Release 建置
cargo test --workspace         # 執行所有測試
cargo clippy --workspace       # Lint 檢查
cargo fmt --all                # 格式化
cargo bench                    # 效能基準測試
```

### 撰寫規則

規則為 YAML 檔案，使用 tree-sitter S-expression 模式：

```yaml
id: atlas/security/typescript/sql-injection
name: SQL Injection via String Concatenation
severity: critical
category: security
language: TypeScript
cwe_id: CWE-89
pattern: |
  (call_expression
    function: (member_expression
      property: (property_identifier) @method
      (#match? @method "^(query|execute)$"))
    arguments: (arguments
      (template_string) @sql_template))
  @match
remediation: >
  Use parameterized queries instead of string concatenation.
```

規則檔案放置於 `rules/builtin/{language}/{rule-name}.yaml`，測試 fixture 放置於 `rules/builtin/{language}/tests/{rule-name}/fail.{ext}` 和 `pass.{ext}`。

## License

Proprietary. See LICENSE for details.
