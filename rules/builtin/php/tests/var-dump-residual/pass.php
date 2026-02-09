<?php
// 良好：使用日誌框架
$logger->debug('User data', ['user' => $userData]);

// 良好：使用 error_log
error_log(json_encode($response));

// 良好：使用 print_r 搭配 return 模式寫入日誌
$output = print_r($config, true);
$logger->info($output);
