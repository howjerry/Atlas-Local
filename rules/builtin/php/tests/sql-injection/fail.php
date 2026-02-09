<?php
// 不安全：使用字串插值組合 SQL 查詢
$userId = $_GET['id'];
$result = mysql_query("SELECT * FROM users WHERE id = $userId");

// 不安全：使用字串串接組合 SQL 查詢
$name = $_POST['name'];
$result2 = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");

// 不安全：PDO query 使用字串插值
$pdo->query("DELETE FROM orders WHERE id = $orderId");
