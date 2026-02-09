<?php
// 良好：catch 區塊有記錄錯誤
try {
    $data = fetchData();
} catch (Exception $e) {
    error_log($e->getMessage());
}

// 良好：catch 區塊重新拋出例外
try {
    $conn = new PDO($dsn);
} catch (PDOException $e) {
    throw new RuntimeException('Database connection failed', 0, $e);
}
