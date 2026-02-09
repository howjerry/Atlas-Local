<?php
// 安全：使用 prepared statements 搭配參數綁定
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);

// 安全：使用 MySQLi prepared statements
$stmt = $mysqli->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();

// 安全：使用常數字串（非動態組合）
$result = pg_query($conn, 'SELECT * FROM config');
