<?php
// 安全：使用 json_decode 代替 unserialize
$data = json_decode($jsonString, true);

// 安全：使用 json_decode 處理 API 回應
$response = json_decode(file_get_contents('php://input'), true);

// 安全：使用具型別的資料存取
$config = new AppConfig();
$config->loadFromArray($row['settings']);
