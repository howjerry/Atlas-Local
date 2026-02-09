<?php
// 安全：使用硬編碼路徑
include 'config/database.php';
require 'vendor/autoload.php';
include_once 'helpers/utils.php';
require_once 'bootstrap/app.php';

// 安全：使用 __DIR__ 常數
require __DIR__ . '/config.php';
