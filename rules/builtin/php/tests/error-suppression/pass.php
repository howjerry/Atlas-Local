<?php
// 良好：使用 try-catch 處理錯誤
try {
    $value = file_get_contents('missing.txt');
} catch (Exception $e) {
    $value = null;
    error_log($e->getMessage());
}

// 良好：先檢查後操作
if ($b !== 0) {
    $result = $a / $b;
}

// 良好：使用 isset 檢查
$item = isset($array['missing_key']) ? $array['missing_key'] : null;

// 良好：使用 null 合併運算子
$item = $array['missing_key'] ?? null;
