<?php
// Log Injection: should NOT trigger the rule
// 使用硬編碼字串或結構化日誌

// 安全：使用硬編碼字串
error_log("Application started");

// 安全：使用 Monolog 結構化日誌
$logger->info('User login', ['username' => $username]);

