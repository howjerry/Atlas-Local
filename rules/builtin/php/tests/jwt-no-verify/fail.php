<?php
// JWT No Verify: SHOULD trigger the rule
// Pattern: JWT 手動解碼跳過簽名驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

// 不安全：手動解碼 JWT payload，跳過簽名驗證
$parts = explode('.', $token);
$payload = json_decode(base64_decode($parts[1]));

// 不安全：decode 帶 verify=false
$decoded = $jwt->decode($token, false);

