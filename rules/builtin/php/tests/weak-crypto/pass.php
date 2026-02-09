<?php
// 安全：使用 password_hash 雜湊密碼
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// 安全：使用 hash 搭配 SHA-256
$token = hash('sha256', $secret);

// 安全：使用 hash_hmac 做訊息驗證
$signature = hash_hmac('sha256', $data, $key);

// 安全：驗證密碼
$valid = password_verify($input, $hashedPassword);
