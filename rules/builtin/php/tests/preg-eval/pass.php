<?php
// preg-eval: should NOT trigger the rule
// 使用 preg_replace_callback 代替 /e 修飾符

// 安全：使用 preg_replace_callback
preg_replace_callback('/pattern/', function($matches) {
    return strtoupper($matches[1]);
}, $subject);

// 安全：使用硬編碼 pattern 不含 /e
preg_replace('/[^a-zA-Z0-9]/', '', $input);

