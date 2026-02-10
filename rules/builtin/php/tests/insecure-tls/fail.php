<?php
// Insecure TLS: SHOULD trigger the rule
// Pattern: curl 停用 SSL 憑證驗證
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

$ch = curl_init();

// 不安全：停用 SSL 憑證驗證
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// 不安全：停用主機名驗證
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

