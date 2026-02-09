<?php
// 不良：使用 global 關鍵字引入全域變數
function getConfig() {
    global $config;
    return $config['database'];
}

// 不良：在函式中使用多個 global 變數
function processRequest() {
    global $db, $logger;
    $logger->info('Processing request');
    return $db->query('SELECT 1');
}
