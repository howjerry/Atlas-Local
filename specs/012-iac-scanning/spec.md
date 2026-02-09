# Feature Specification: Atlas Local — Infrastructure as Code Scanning

**Feature Branch**: `012-iac-scanning`
**Created**: 2026-02-08
**Status**: Draft
**Depends On**: 001-atlas-local-sast (core scanning engine, finding model, policy gating, report formats)

## Overview & Scope

Atlas-Local currently scans application source code but does not analyse Infrastructure as Code (IaC) configurations. Misconfigured infrastructure is a leading cause of cloud security breaches. This specification adds IaC scanning for Terraform (HCL), Kubernetes manifests (YAML), and Dockerfiles, detecting security misconfigurations before deployment.

**Purpose**: Enable DevOps and security teams to detect infrastructure security misconfigurations in Terraform, Kubernetes, and Docker configurations using the same Atlas workflow, policy gating, and reporting as application code.

**Scope**: Three IaC formats with format-specific parsers and rule engines. At least 25 IaC rules. Integration with existing finding/gate/report pipeline.

**Exclusions** (deferred to future specs):
- CloudFormation (AWS) or ARM/Bicep (Azure) template scanning
- Ansible playbook scanning
- Helm chart analysis (beyond rendered YAML manifests)
- Cloud runtime posture comparison (drift detection)
- Auto-remediation (generating fix patches for IaC files)
- Pulumi or CDK (programmatic IaC via source code — already covered by SAST)

## User Scenarios & Testing *(mandatory)*

### User Story 1 — DevOps Engineer Scans Terraform Before Apply (Priority: P1)

A DevOps engineer runs `atlas scan ./infrastructure` before `terraform apply`. Atlas detects that an S3 bucket has public access enabled, a security group allows ingress from `0.0.0.0/0` on port 22, and an RDS instance has no encryption at rest. Each finding includes the resource type, resource name, and remediation guidance.

**Why this priority**: Terraform misconfigurations are the most common source of cloud security incidents. Catching them before apply prevents deployments of insecure infrastructure.

**Independent Test**: Create a Terraform configuration with known misconfigurations, scan it, and verify findings are produced with correct resource types, resource names, and remediation text.

**Acceptance Scenarios**:

1. **Given** a Terraform file with `resource "aws_s3_bucket" "data" {}` (no bucket policy or ACL restricting public access), **When** scanned, **Then** a finding is produced with `rule_id: "atlas/iac/terraform/s3-public-access"`, `severity: "high"`, and `metadata.resource_type: "aws_s3_bucket"`.
2. **Given** a security group with `cidr_blocks = ["0.0.0.0/0"]` on port 22, **When** scanned, **Then** a finding is produced: "Security group allows SSH access from any IP."
3. **Given** a properly configured Terraform file with encrypted S3 buckets and restricted security groups, **When** scanned, **Then** zero IaC findings are produced.

---

### User Story 2 — Security Team Reviews Kubernetes Manifests (Priority: P1)

A security team scans Kubernetes deployment manifests before applying them to a cluster. Atlas detects containers running as root, missing resource limits, privileged containers, and images using the `latest` tag.

**Why this priority**: Kubernetes misconfigurations can lead to container escapes, denial of service, and privilege escalation. These are highly actionable findings.

**Independent Test**: Create Kubernetes YAML with known misconfigurations and verify all expected findings are produced.

**Acceptance Scenarios**:

1. **Given** a Kubernetes deployment with `securityContext.runAsRoot: true`, **When** scanned, **Then** a finding is produced: "Container runs as root user."
2. **Given** a pod spec with no `resources.limits`, **When** scanned, **Then** a finding is produced: "Container has no resource limits."
3. **Given** a container with `image: nginx:latest`, **When** scanned, **Then** a finding is produced: "Container image uses 'latest' tag."

---

### User Story 3 — Developer Checks Dockerfile Security (Priority: P2)

A developer scans their Dockerfile for common security issues. Atlas detects running as root (no `USER` directive), using `ADD` instead of `COPY`, and pinning to `latest` base images.

**Why this priority**: Dockerfile security is important but less complex than Terraform/K8s. The rule set is smaller and the parser is simpler.

**Independent Test**: Create a Dockerfile with known issues and verify findings are produced.

**Acceptance Scenarios**:

1. **Given** a Dockerfile with no `USER` directive, **When** scanned, **Then** a finding is produced: "Dockerfile does not set a non-root USER."
2. **Given** a Dockerfile with `FROM node:latest`, **When** scanned, **Then** a finding is produced: "Base image uses 'latest' tag; pin to a specific version."
3. **Given** a Dockerfile with `ADD https://example.com/file.tar.gz /app/`, **When** scanned, **Then** a finding is produced: "Use COPY instead of ADD for local files."

---

### User Story 4 — CI Pipeline Gates on IaC Misconfigurations (Priority: P2)

A DevSecOps engineer configures the CI pipeline to fail if any Critical or High IaC findings exist. IaC findings are gated separately from application code findings using `category_overrides.iac`.

**Why this priority**: CI gating enforces IaC security policies, but requires the detection engine (US1-3) to work first.

**Independent Test**: Configure policy with IaC thresholds, scan an IaC directory with High findings, and verify the gate fails.

**Acceptance Scenarios**:

1. **Given** a policy with `category_overrides: { iac: { high: 0 } }` and a Terraform file with a High-severity finding, **When** scanned, **Then** the gate fails.
2. **Given** a scan of only source code (no IaC files), **When** scanned, **Then** no IaC findings are produced and the gate evaluates only SAST findings.

---

### Edge Cases

- What happens with Terraform modules (referenced directories)? Only local `.tf` files are scanned. Remote module references are not resolved or downloaded.
- What happens with Kubernetes files containing multiple documents (YAML `---` separator)? Each document is parsed independently as a separate resource.
- What happens with Dockerfile `ARG` used in `FROM`? The `FROM` line is analysed as-is. ARG substitution is not performed.
- What happens when a `.yaml` file is not a Kubernetes manifest? The IaC engine checks for `apiVersion` and `kind` fields to identify Kubernetes manifests. Non-K8s YAML files are ignored.
- What happens with HCL2 (Terraform 0.12+) syntax? The `tree-sitter-hcl` grammar supports HCL2 syntax. Older HCL1 syntax is not supported.

## Requirements *(mandatory)*

### Functional Requirements

**Terraform Scanning**

- **FR-I01**: Atlas MUST parse Terraform files (`.tf`) using the `tree-sitter-hcl` grammar.
- **FR-I02**: Terraform rules MUST be defined as L1 declarative YAML rules using tree-sitter HCL patterns (same format as SAST rules).
- **FR-I03**: At least 10 Terraform rules MUST be implemented covering: public access, encryption, logging, network exposure, and IAM misconfigurations.
- **FR-I04**: Terraform findings MUST include `metadata.resource_type` and `metadata.resource_name` extracted from the HCL AST.

**Kubernetes Scanning**

- **FR-I05**: Atlas MUST parse Kubernetes manifest files (`.yaml`, `.yml`) containing `apiVersion` and `kind` fields.
- **FR-I06**: Kubernetes rules MUST use a YAML path-based matcher (not tree-sitter) that evaluates structured conditions against parsed YAML documents.
- **FR-I07**: At least 10 Kubernetes rules MUST be implemented covering: root containers, resource limits, privileged mode, image tags, network policies, and security contexts.
- **FR-I08**: Kubernetes findings MUST include `metadata.resource_type` (Kind) and `metadata.resource_name`.

**Dockerfile Scanning**

- **FR-I09**: Atlas MUST parse Dockerfiles using a line-level instruction parser (FROM, RUN, COPY, ADD, USER, EXPOSE, etc.).
- **FR-I10**: At least 5 Dockerfile rules MUST be implemented covering: root user, latest tag, ADD vs COPY, exposed secrets, and hardcoded credentials.
- **FR-I11**: Dockerfile findings MUST include `metadata.instruction` (e.g., "FROM", "RUN").

**Finding Model**

- **FR-I12**: A new `Category::Iac` enum variant MUST be added to the Category enum.
- **FR-I13**: IaC findings MUST include `metadata.iac_type` with value `"terraform"`, `"kubernetes"`, or `"dockerfile"`.
- **FR-I14**: IaC findings MUST participate in gate evaluation under `category_overrides.iac`.

**File Detection**

- **FR-I15**: Terraform files MUST be detected by `.tf` extension.
- **FR-I16**: Kubernetes manifests MUST be detected by `.yaml`/`.yml` extension AND presence of `apiVersion` + `kind` fields in the YAML content.
- **FR-I17**: Dockerfiles MUST be detected by filename matching: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`.

### Key Entities

- **IacRuleConfig**: Configuration for a YAML path-based rule (Kubernetes). Key attributes: `id`, `path_conditions[]`, `severity`, `description`.
- **PathCondition**: A single condition in a YAML path matcher. Key attributes: `path` (dot-separated), `operator` (equals/exists/not_exists/matches), `value`.
- **IacFinding**: A finding for an IaC misconfiguration. Extends `Finding` with IaC-specific metadata.
- **IacType**: The type of IaC configuration. Values: `Terraform`, `Kubernetes`, `Dockerfile`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-I01**: 10 Terraform rules detect the targeted misconfigurations with 100% recall on a curated test corpus of 20 Terraform files.
- **SC-I02**: 10 Kubernetes rules detect the targeted misconfigurations with 100% recall on a curated test corpus of 20 K8s manifests.
- **SC-I03**: 5 Dockerfile rules detect the targeted issues with 100% recall on a curated test corpus of 10 Dockerfiles.
- **SC-I04**: IaC scan of a directory with 100 Terraform files, 50 K8s manifests, and 10 Dockerfiles completes in < 10 seconds.
- **SC-I05**: IaC findings include correct `resource_type` and `resource_name` metadata for Terraform and Kubernetes.
- **SC-I06**: `category_overrides.iac` correctly gates IaC findings independently from SAST/SCA findings.
- **SC-I07**: All existing SAST tests pass without modification (zero regression from `Category::Iac` addition).
- **SC-I08**: False positive rate is < 10% when tested against 5 public Terraform/K8s repositories.

## Assumptions

- `tree-sitter-hcl` crate is available on crates.io and supports HCL2 syntax.
- Kubernetes manifest YAML is parseable by standard YAML libraries (`serde_yaml`).
- Dockerfile instruction format is stable and well-documented.
- IaC file detection can be performed during the existing file discovery phase.

## Scope Boundaries

**In Scope**:
- Terraform HCL scanning via tree-sitter-hcl (10+ rules)
- Kubernetes YAML scanning via path-based matcher (10+ rules)
- Dockerfile scanning via line-level parser (5+ rules)
- `Category::Iac` enum variant
- IaC-specific metadata (resource_type, resource_name, iac_type)
- Gate integration (`category_overrides.iac`)
- JSON/SARIF report integration for IaC findings
- IaC file detection by extension and content

**Out of Scope**:
- CloudFormation, ARM/Bicep templates
- Ansible playbooks
- Helm chart rendering
- Cloud runtime drift detection
- Auto-remediation patches
- Remote Terraform module resolution

## Implementation Notes

### Files to Create

| File | Purpose |
|------|---------|
| `crates/atlas-analysis/src/iac_matcher.rs` | YAML path-based rule matcher for Kubernetes |
| `crates/atlas-analysis/src/dockerfile_parser.rs` | Line-level Dockerfile parser |
| `rules/builtin/terraform/*.yaml` | 10+ Terraform rules (tree-sitter HCL patterns) |
| `rules/builtin/kubernetes/*.yaml` | 10+ Kubernetes rules (path-based conditions) |
| `rules/builtin/dockerfile/*.yaml` | 5+ Dockerfile rules |
| Test fixtures for each rule | `fail.*` and `pass.*` per rule |

### Files to Modify

| File | Change |
|------|--------|
| `crates/atlas-rules/src/lib.rs` | Add `Category::Iac` variant |
| `crates/atlas-core/src/engine.rs` | Integrate IaC scanning in file discovery |
| `crates/atlas-cli/src/commands/scan.rs` | IaC file detection |
| `crates/atlas-policy/src/gate.rs` | Support `category_overrides.iac` |
| `crates/atlas-report/src/json.rs` | IaC findings in JSON output |
| `crates/atlas-report/src/sarif.rs` | IaC findings in SARIF output |
| `Cargo.toml` | Add `tree-sitter-hcl` dependency |

### Kubernetes YAML Path Matcher

Unlike Terraform (tree-sitter) and SAST (tree-sitter), Kubernetes rules use a YAML path-based matcher because:
1. YAML has no tree-sitter grammar suitable for security analysis
2. Kubernetes schemas are well-defined — path-based access is natural
3. Conditions like "spec.containers[*].securityContext.runAsRoot" are more intuitive as paths than as tree patterns
4. The matcher is simpler and faster than a full tree-sitter integration

### IaC Rule Inventory

#### Terraform Rules (10)

| # | Rule ID | Description | Severity |
|---|---------|------------|----------|
| 1 | `atlas/iac/terraform/s3-public-access` | S3 bucket allows public access | High |
| 2 | `atlas/iac/terraform/sg-unrestricted-ingress` | Security group allows unrestricted ingress | High |
| 3 | `atlas/iac/terraform/rds-no-encryption` | RDS instance without encryption at rest | High |
| 4 | `atlas/iac/terraform/s3-no-encryption` | S3 bucket without server-side encryption | Medium |
| 5 | `atlas/iac/terraform/cloudtrail-disabled` | CloudTrail logging not enabled | Medium |
| 6 | `atlas/iac/terraform/iam-wildcard-action` | IAM policy with wildcard (*) action | High |
| 7 | `atlas/iac/terraform/ebs-no-encryption` | EBS volume without encryption | Medium |
| 8 | `atlas/iac/terraform/rds-public-access` | RDS instance publicly accessible | Critical |
| 9 | `atlas/iac/terraform/s3-no-versioning` | S3 bucket without versioning | Low |
| 10 | `atlas/iac/terraform/sg-ssh-open` | SSH port (22) open to the internet | High |

#### Kubernetes Rules (10)

| # | Rule ID | Description | Severity |
|---|---------|------------|----------|
| 1 | `atlas/iac/kubernetes/container-root` | Container runs as root | High |
| 2 | `atlas/iac/kubernetes/no-resource-limits` | Container has no resource limits | Medium |
| 3 | `atlas/iac/kubernetes/privileged-container` | Container runs in privileged mode | Critical |
| 4 | `atlas/iac/kubernetes/latest-tag` | Container uses 'latest' image tag | Medium |
| 5 | `atlas/iac/kubernetes/no-readiness-probe` | Container has no readiness probe | Low |
| 6 | `atlas/iac/kubernetes/host-network` | Pod uses host network | High |
| 7 | `atlas/iac/kubernetes/host-pid` | Pod uses host PID namespace | High |
| 8 | `atlas/iac/kubernetes/no-security-context` | Container has no security context | Medium |
| 9 | `atlas/iac/kubernetes/writable-rootfs` | Container has writable root filesystem | Medium |
| 10 | `atlas/iac/kubernetes/capability-added` | Container adds dangerous capabilities | High |

#### Dockerfile Rules (5)

| # | Rule ID | Description | Severity |
|---|---------|------------|----------|
| 1 | `atlas/iac/dockerfile/no-user` | Dockerfile does not set a non-root USER | High |
| 2 | `atlas/iac/dockerfile/latest-tag` | Base image uses 'latest' tag | Medium |
| 3 | `atlas/iac/dockerfile/add-instead-of-copy` | Uses ADD instead of COPY for local files | Low |
| 4 | `atlas/iac/dockerfile/run-sudo` | Uses sudo in RUN instruction | Medium |
| 5 | `atlas/iac/dockerfile/expose-sensitive-port` | Exposes SSH or database ports | Medium |

## References

| Resource | Purpose |
|----------|---------|
| `specs/001-atlas-local-sast/spec.md` | Parent feature specification |
| [CIS Benchmarks](https://www.cisecurity.org/benchmark) | IaC security benchmark reference |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Terraform security scanner reference |
| [kubesec](https://kubesec.io/) | Kubernetes security scanner reference |
| [hadolint](https://github.com/hadolint/hadolint) | Dockerfile linter reference |
| [tree-sitter-hcl](https://github.com/tree-sitter-grammars/tree-sitter-hcl) | HCL grammar |
