<?php
// 不良：空的 catch 區塊，靜默吞掉例外
try {
    $data = fetchData();
} catch (Exception $e) {
}

// 不良：另一個空的 catch 區塊
try {
    $conn = new PDO($dsn);
} catch (PDOException $e) {
}
