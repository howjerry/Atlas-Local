// 應該被偵測：包含 private key header 的字串

const rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;

const ecKey = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII...";

const opensshKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...
-----END OPENSSH PRIVATE KEY-----`;

const dsaKey = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQD...";

const genericKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----`;
