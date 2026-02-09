# Data Model: Infrastructure as Code Scanning

**Feature**: 012-iac-scanning
**Created**: 2026-02-08
**Purpose**: Define the IaC rule configuration, YAML path matcher, Dockerfile parser, and finding data models.

## 1. IaC Types

### Rust Type

```rust
/// The type of Infrastructure as Code configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IacType {
    /// Terraform HCL files (.tf).
    Terraform,
    /// Kubernetes manifest YAML files.
    Kubernetes,
    /// Dockerfiles.
    Dockerfile,
}
```

### File Detection Logic

| IaC Type | Detection Method |
|----------|-----------------|
| Terraform | File extension `.tf` |
| Kubernetes | Extension `.yaml`/`.yml` AND contains `apiVersion:` AND contains `kind:` |
| Dockerfile | Filename matches: `Dockerfile`, `Dockerfile.*`, `*.dockerfile` |

## 2. Terraform Rules (tree-sitter HCL)

Terraform rules use the same L1 declarative YAML format as SAST rules, with `tree-sitter-hcl` patterns.

### Rule YAML Example

```yaml
id: atlas/iac/terraform/s3-public-access
name: S3 Bucket Public Access
description: >
  Detects AWS S3 bucket resources that do not explicitly block public access.
  Public S3 buckets are a leading cause of cloud data breaches.
severity: high
category: iac
language: Terraform
pattern: |
  (block
    (identifier) @resource_type
    (string_lit) @resource_label
    (body) @body)
  (#eq? @resource_type "resource")
  (#match? @resource_label "aws_s3_bucket")
  @match
remediation: >
  Add an aws_s3_bucket_public_access_block resource to explicitly block
  all public access. Set block_public_acls, block_public_policy,
  ignore_public_acls, and restrict_public_buckets all to true.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
tags:
  - cloud-security
  - aws
  - s3
version: 1.0.0
confidence: medium
metadata:
  iac_type: "terraform"
  resource_type: "aws_s3_bucket"
```

### HCL AST Node Types (tree-sitter-hcl)

| HCL Construct | AST Node | Fields |
|--------------|----------|--------|
| `resource "type" "name" {}` | `block` | `(identifier) (string_lit) (string_lit) (body)` |
| `attribute = value` | `attribute` | `(identifier) (expression)` |
| `"string"` | `string_lit` | Text content |
| `true` / `false` | `literal_value` | Boolean |
| `["a", "b"]` | `tuple` | Elements |
| `{ key = value }` | `object` | Key-value pairs |

## 3. Kubernetes Rules (YAML Path Matcher)

Kubernetes rules use a path-based condition matcher that evaluates structured conditions against parsed YAML.

### Rule YAML Format

```yaml
id: atlas/iac/kubernetes/container-root
name: Container Running as Root
description: >
  Detects Kubernetes containers that run as the root user. Running
  containers as root increases the blast radius of container escapes.
severity: high
category: iac
language: Kubernetes
# Kubernetes rules use path_conditions instead of tree-sitter patterns
path_conditions:
  - path: "kind"
    operator: "in"
    value: ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
  - path: "spec.template.spec.containers[*].securityContext.runAsNonRoot"
    operator: "not_exists"
  - path: "spec.template.spec.securityContext.runAsNonRoot"
    operator: "not_exists"
remediation: >
  Set securityContext.runAsNonRoot to true at the pod or container level.
  Specify a non-root runAsUser (e.g., 1000).
references:
  - https://kubernetes.io/docs/concepts/security/pod-security-standards/
tags:
  - cloud-security
  - kubernetes
  - container-security
version: 1.0.0
confidence: high
metadata:
  iac_type: "kubernetes"
```

### Path Condition Schema

```rust
/// A condition to evaluate against a YAML document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    /// Dot-separated path into the YAML structure.
    /// Supports `[*]` for array wildcard and `[N]` for index.
    pub path: String,
    /// The comparison operator.
    pub operator: PathOperator,
    /// The expected value (interpretation depends on operator).
    pub value: Option<serde_yaml::Value>,
}

/// Operators for YAML path conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOperator {
    /// Path value equals the expected value.
    Equals,
    /// Path value does not equal the expected value.
    NotEquals,
    /// Path exists in the document.
    Exists,
    /// Path does not exist in the document.
    NotExists,
    /// Path value matches a regex pattern.
    Matches,
    /// Path value is in a list of expected values.
    In,
    /// Path value is greater than the expected value.
    GreaterThan,
    /// Path value is less than the expected value.
    LessThan,
}
```

### Path Expression Syntax

| Expression | Meaning | Example |
|-----------|---------|---------|
| `kind` | Top-level key | `"Deployment"` |
| `spec.replicas` | Nested key | `3` |
| `spec.containers[0].name` | Array index | `"nginx"` |
| `spec.containers[*].image` | Array wildcard (any element) | `"nginx:latest"` |
| `metadata.labels.app` | Deeply nested key | `"my-app"` |
| `spec.template.spec.volumes[*].hostPath` | Nested array wildcard | `{"path": "/var/run"}` |

### Path Matcher Algorithm

```
function evaluate_rule(document, path_conditions):
    for condition in path_conditions:
        values = resolve_path(document, condition.path)
        match condition.operator:
            Exists     → if values is empty: return false
            NotExists  → if values is not empty: return false
            Equals     → if no value equals condition.value: return false
            NotEquals  → if any value equals condition.value: return false
            Matches    → if no value matches regex: return false
            In         → if no value is in condition.value list: return false
            GreaterThan → if no value > condition.value: return false
            LessThan    → if no value < condition.value: return false
    return true  // All conditions met → finding produced
```

## 4. Dockerfile Rules (Line-Level Parser)

Dockerfile rules use a simplified instruction-level parser.

### Parsed Instruction

```rust
/// A parsed Dockerfile instruction.
#[derive(Debug, Clone)]
pub struct DockerInstruction {
    /// The instruction keyword (uppercase).
    pub keyword: String,       // "FROM", "RUN", "COPY", "ADD", "USER", "EXPOSE", etc.
    /// The instruction arguments (everything after the keyword).
    pub arguments: String,
    /// Line number in the Dockerfile (1-based).
    pub line: usize,
}
```

### Rule YAML Format

```yaml
id: atlas/iac/dockerfile/no-user
name: Dockerfile Missing Non-Root USER
description: >
  Detects Dockerfiles that do not set a non-root USER directive.
  Without USER, the container runs as root by default.
severity: high
category: iac
language: Dockerfile
# Dockerfile rules use instruction_conditions
instruction_conditions:
  - type: "absence"
    keyword: "USER"
    description: "No USER instruction found"
  # Exclusion: if USER is present but set to "root", also flag it
remediation: >
  Add a USER directive with a non-root user: USER 1000 or USER appuser.
  Create the user in a previous RUN instruction if needed.
references:
  - https://docs.docker.com/develop/develop-images/instructions/#user
tags:
  - container-security
  - dockerfile
version: 1.0.0
confidence: high
metadata:
  iac_type: "dockerfile"
```

### Instruction Condition Schema

```rust
/// A condition to evaluate against Dockerfile instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionCondition {
    /// Type of condition.
    pub condition_type: InstructionConditionType,
    /// The instruction keyword to match (e.g., "FROM", "USER").
    pub keyword: String,
    /// Pattern to match in the instruction arguments.
    pub pattern: Option<String>,
    /// Human-readable description.
    pub description: String,
}

/// Types of Dockerfile instruction conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionConditionType {
    /// The instruction must be absent from the Dockerfile.
    Absence,
    /// The instruction is present and its arguments match the pattern.
    Matches,
    /// The instruction is present and its arguments do NOT match the pattern.
    NotMatches,
}
```

## 5. IaC Finding

### JSON Example (Terraform)

```json
{
  "fingerprint": "iac-tf-abc123...",
  "rule_id": "atlas/iac/terraform/s3-public-access",
  "severity": "high",
  "category": "iac",
  "file_path": "infrastructure/main.tf",
  "line_range": {
    "start_line": 15,
    "start_col": 1,
    "end_line": 25,
    "end_col": 1
  },
  "snippet": "resource \"aws_s3_bucket\" \"data\" {",
  "description": "S3 bucket 'data' does not have public access blocked. Public S3 buckets are a leading cause of data breaches.",
  "remediation": "Add aws_s3_bucket_public_access_block to block all public access.",
  "analysis_level": "L1",
  "confidence": "medium",
  "metadata": {
    "iac_type": "terraform",
    "resource_type": "aws_s3_bucket",
    "resource_name": "data"
  }
}
```

### JSON Example (Kubernetes)

```json
{
  "fingerprint": "iac-k8s-def456...",
  "rule_id": "atlas/iac/kubernetes/container-root",
  "severity": "high",
  "category": "iac",
  "file_path": "k8s/deployment.yaml",
  "line_range": {
    "start_line": 1,
    "start_col": 1,
    "end_line": 30,
    "end_col": 1
  },
  "snippet": "apiVersion: apps/v1\nkind: Deployment",
  "description": "Container in Deployment 'web-app' runs as root user. Set securityContext.runAsNonRoot to true.",
  "remediation": "Add securityContext.runAsNonRoot: true to the pod or container spec.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "iac_type": "kubernetes",
    "resource_type": "Deployment",
    "resource_name": "web-app"
  }
}
```

### JSON Example (Dockerfile)

```json
{
  "fingerprint": "iac-docker-ghi789...",
  "rule_id": "atlas/iac/dockerfile/no-user",
  "severity": "high",
  "category": "iac",
  "file_path": "Dockerfile",
  "line_range": {
    "start_line": 1,
    "start_col": 1,
    "end_line": 1,
    "end_col": 1
  },
  "snippet": "FROM node:18-alpine",
  "description": "Dockerfile does not set a non-root USER. Container will run as root by default.",
  "remediation": "Add 'USER 1000' or 'USER appuser' after installing dependencies.",
  "analysis_level": "L1",
  "confidence": "high",
  "metadata": {
    "iac_type": "dockerfile",
    "instruction": "USER (absent)"
  }
}
```

## 6. IaC Scan Pipeline

```
atlas scan ./project
  │
  ├─ File Discovery
  │   ├─ .ts/.java/.py/.go/.cs → SAST rules
  │   ├─ .tf → Terraform IaC rules (tree-sitter-hcl)
  │   ├─ .yaml/.yml (with apiVersion+kind) → Kubernetes IaC rules (path matcher)
  │   ├─ Dockerfile* → Dockerfile IaC rules (instruction parser)
  │   └─ lockfiles → SCA (if spec 008 implemented)
  │
  ├─ IaC Analysis
  │   ├─ Terraform: Parse HCL AST → Run L1 patterns → Findings
  │   ├─ Kubernetes: Parse YAML → Evaluate path conditions → Findings
  │   └─ Dockerfile: Parse instructions → Evaluate conditions → Findings
  │
  ├─ Merge SAST + SCA + IaC findings
  │
  ├─ Gate Evaluation
  │   ├─ category_overrides.security → SAST security findings
  │   ├─ category_overrides.quality → SAST quality findings
  │   ├─ category_overrides.sca → SCA findings
  │   └─ category_overrides.iac → IaC findings
  │
  └─ Report Output (JSON/SARIF/JSONL)
```

## 7. Category Enum Extension

```rust
// Before (with spec 008)
pub enum Category {
    Security,
    Quality,
    Secrets,
    Sca,     // from spec 008
}

// After (with spec 012)
pub enum Category {
    Security,
    Quality,
    Secrets,
    Sca,     // from spec 008
    Iac,     // from spec 012
    Metrics, // from spec 007 (if implemented)
}
```

### Impact on Existing Code

| File | Change Required |
|------|----------------|
| `crates/atlas-rules/src/lib.rs` | Add `Iac` variant |
| `crates/atlas-policy/src/policy.rs` | Add `iac` to `CategoryOverrides` |
| `crates/atlas-policy/src/gate.rs` | Add `iac` to `CategoryCounts` |
| `crates/atlas-report/src/sarif.rs` | Map `Iac` to SARIF properties |
| `crates/atlas-report/src/json.rs` | Include `iac` in JSON summary |
| `crates/atlas-cli/src/commands/scan.rs` | Add `Iac` to `FindingAdapter` |

### Recommended Approach

If specs 007, 008, and 012 are developed concurrently:
1. Add all three Category variants (`Metrics`, `Sca`, `Iac`) in a single foundational PR
2. Each spec then implements its analysis engine on top of the shared enum
3. This avoids repeated breaking changes to `Category` and its downstream consumers
