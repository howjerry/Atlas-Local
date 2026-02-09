## ADDED Requirements

### Requirement: Expanded secrets detection coverage
The system SHALL expand secrets detection from 6 rules to at least 15 rules, covering major cloud providers and SaaS service tokens.

#### Scenario: GCP API key detected
- **WHEN** a file contains a string matching `AIza[0-9A-Za-z_-]{35}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/gcp-api-key"` and `severity: high`

#### Scenario: Azure storage account key detected
- **WHEN** a file contains an Azure storage account key (88-character Base64 string in storage key context)
- **THEN** a finding is produced with `rule_id: "atlas/secrets/azure-storage-key"` and `severity: high`

#### Scenario: GitHub personal access token detected
- **WHEN** a file contains a string matching `ghp_[A-Za-z0-9]{36}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/github-pat"` and `severity: high`

#### Scenario: GitLab personal access token detected
- **WHEN** a file contains a string matching `glpat-[A-Za-z0-9_-]{20}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/gitlab-pat"` and `severity: high`

### Requirement: SaaS service token detection
The system SHALL detect tokens for Slack, Stripe, Twilio, SendGrid, and JWT secrets.

#### Scenario: Slack webhook URL detected
- **WHEN** a file contains `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/slack-webhook"` and `severity: medium`

#### Scenario: Stripe secret key detected
- **WHEN** a file contains a string matching `sk_live_[A-Za-z0-9]{24,}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/stripe-secret-key"` and `severity: critical`

#### Scenario: Twilio API key detected
- **WHEN** a file contains a string matching `SK[a-f0-9]{32}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/twilio-api-key"` and `severity: high`

#### Scenario: SendGrid API key detected
- **WHEN** a file contains a string matching `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`
- **THEN** a finding is produced with `rule_id: "atlas/secrets/sendgrid-api-key"` and `severity: high`

#### Scenario: Hardcoded JWT secret detected
- **WHEN** a file contains a `jwt_secret` or `jwt-secret` assignment with a string literal value
- **THEN** a finding is produced with `rule_id: "atlas/secrets/jwt-secret"` and `severity: high`

### Requirement: Secrets rule test fixtures
Every new secrets rule SHALL have a `fail.txt` and `pass.txt` test fixture.

#### Scenario: All secrets rules have test fixtures
- **WHEN** secrets rules are loaded from disk
- **THEN** each rule has corresponding `rules/builtin/secrets/tests/{rule-name}/fail.txt` and `pass.txt` files

#### Scenario: Safe configuration produces no findings
- **WHEN** a file contains placeholder values like `YOUR_API_KEY_HERE` or environment variable references
- **THEN** no secrets finding is produced
