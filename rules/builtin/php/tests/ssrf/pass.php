<?php
// 安全：使用硬編碼的內部 API URL
$content = file_get_contents('https://api.internal.example.com/data');

// 安全：使用白名單驗證 URL
$allowedHosts = ['api.example.com', 'cdn.example.com'];
$parsed = parse_url($requestUrl);
if (in_array($parsed['host'], $allowedHosts)) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://' . $parsed['host'] . $parsed['path']);
}
