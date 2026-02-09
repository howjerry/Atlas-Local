<?php
// 良好：使用日誌框架
$logger->debug('User data', ['user' => $userData]);

// 良好：使用 error_log 記錄
error_log(json_encode($config));

// 良好：使用 json_encode 序列化
$json = json_encode($results, JSON_PRETTY_PRINT);
file_put_contents('debug.log', $json);
