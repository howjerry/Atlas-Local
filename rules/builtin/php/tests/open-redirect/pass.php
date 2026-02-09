<?php
// 安全：使用硬編碼路徑
header('Location: /dashboard');

// 安全：使用白名單驗證
$allowed = ['/home', '/profile', '/settings'];
if (in_array($redirectPath, $allowed)) {
    header('Location: ' . $redirectPath);
}

// 安全：使用 parse_url 驗證域名
$parsed = parse_url($url);
if ($parsed['host'] === 'example.com') {
    header('Location: ' . $url);
}
