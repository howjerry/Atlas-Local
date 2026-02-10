## Why

Atlas-Local 目前僅分析原始碼的安全漏洞，但現代應用程式中超過 80% 的程式碼來自第三方依賴。缺少軟體組成分析（SCA）意味著團隊無法在同一工具中檢測已知的 CVE 漏洞，被迫使用額外的外部工具。新增 SCA 能力讓 Atlas 成為涵蓋原始碼與依賴的完整安全掃描方案。

## What Changes

- 新增 `atlas-sca` crate，負責鎖檔解析、漏洞資料庫管理與匹配引擎
- 支援 6 個套件生態系的鎖檔解析：npm (`package-lock.json`)、Cargo (`Cargo.lock`)、Maven/Gradle (`pom.xml`/`gradle.lockfile`)、Go (`go.sum`)、Python (`requirements.txt`/`Pipfile.lock`)、NuGet (`packages.lock.json`)
- 新增離線 SQLite 漏洞資料庫，透過 Ed25519 簽章驗證的 bundle 更新機制
- 新增 `atlas sca update-db` CLI 指令
- 掃描時自動偵測鎖檔，產生帶有 CVE/CVSS 中繼資料的 SCA findings
- 新增 `Category::Sca` enum variant，整合至既有的 gate/policy/report 管線
- SCA findings 支援 JSON、SARIF、JSONL 報告格式

## Capabilities

### New Capabilities

- `sca-dependency-scanning`: 鎖檔解析、離線漏洞資料庫、版本匹配引擎、SCA finding 產生、資料庫更新指令

### Modified Capabilities

_(無既有 spec 需要修改 — Category::Sca 的新增屬於新能力的實作範圍，不改變既有能力的需求規格)_

## Impact

- **新增 crate**: `atlas-sca`（鎖檔解析、SQLite 資料庫、版本匹配）
- **Category enum**: 新增 `Sca` variant（`atlas-rules`），影響 gate、report、policy 模組的 pattern match
- **CLI**: 新增 `sca update-db` 子指令，scan 指令增加鎖檔自動偵測
- **依賴**: 新增 `rusqlite`（已在 workspace）、`semver`（版本比較）
- **磁碟**: 漏洞資料庫 `~/.atlas/vuln.db`（< 100 MB）
- **下游**: spec 009 (SBOM Generation) 可複用 SCA 解析出的依賴資料
