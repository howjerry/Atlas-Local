<?php
// Log Injection: SHOULD trigger the rule
// Pattern: error_log/syslog 使用字串內插記錄未清理的輸入
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

$username = $_POST['username'];

// 不安全：使用字串內插
error_log("User login attempt: $username");

// 不安全：使用字串串接
error_log("Failed login for: " . $_GET['user']);

// 不安全：syslog 使用字串內插
syslog(LOG_WARNING, "Access denied for $username");

