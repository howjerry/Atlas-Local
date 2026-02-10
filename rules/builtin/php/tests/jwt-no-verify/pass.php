<?php
// JWT No Verify: should NOT trigger the rule
// 使用正確的 JWT 驗證

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// 安全：使用 firebase/php-jwt 搭配金鑰驗證
$decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

