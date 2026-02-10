<?php
// preg-eval: SHOULD trigger the rule
// Pattern: preg_replace 使用 /e 修飾符或動態 pattern
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

// 不安全：使用 /e 修飾符執行程式碼
preg_replace('/.*/e', $_GET['code'], $subject);

// 不安全：使用字串內插組合 pattern（可能包含 /e）
$pattern = "/hello/e";
preg_replace("/$userInput/i", $replacement, $subject);

