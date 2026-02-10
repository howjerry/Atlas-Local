<?php
// Header Injection: should NOT trigger the rule
// 使用硬編碼 header 值

// 安全：使用硬編碼值
header('Content-Type: application/json');

// 安全：使用硬編碼重導向
header('Location: /dashboard');

// 安全：使用 HTTP response code
header('HTTP/1.1 404 Not Found');

