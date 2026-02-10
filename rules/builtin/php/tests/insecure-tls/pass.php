<?php
// Insecure TLS: should NOT trigger the rule
// 使用正確的 SSL 設定

$ch = curl_init();

// 安全：啟用 SSL 憑證驗證
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_CAINFO, '/etc/ssl/certs/ca-certificates.crt');

