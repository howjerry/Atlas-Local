<?php
// 安全：使用 PHP 內建函式代替外部指令
$files = scandir('/var/www/html');

// 安全：使用 escapeshellarg 處理參數
$safeArg = escapeshellarg($userInput);

// 安全：使用 PHP 原生功能
$contents = file_get_contents('/etc/hostname');
$matches = preg_grep('/pattern/', $lines);
