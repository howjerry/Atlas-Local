// Test fixture: hardcoded secrets for secrets detection rules.
// This file intentionally contains fake secret values for testing purposes.
// DO NOT use any of these values in real applications.

// AWS Access Key (should trigger atlas/secrets/generic/aws-access-key)
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// GitHub Personal Access Token (should trigger atlas/secrets/generic/github-token)
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// GitHub OAuth Token
const OAUTH_TOKEN = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

// Generic API Key (should trigger atlas/secrets/generic/generic-api-key)
const api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678";

// Google API Key (should trigger atlas/secrets/generic/google-api-key)
const GOOGLE_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";

// Connection string with password (should trigger atlas/secrets/generic/connection-string-password)
const DB_URL = "postgresql://admin:supersecretpassword@db.example.com:5432/mydb";

// JWT Token (should trigger atlas/secrets/generic/jwt-token)
const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

// High-entropy variable with suspicious name (contextual detection)
const secret_key = "xK9mN2pL5qR8sT1uV4wX7yZ0aB3cD6eF";

// Password assignment
const password = "MyS3cur3P@ssw0rd!2024#AbCdEf";

export { AWS_KEY, GITHUB_TOKEN, OAUTH_TOKEN, api_key, GOOGLE_KEY, DB_URL, JWT, secret_key, password };
