<?php
// 不安全：反序列化使用者輸入
$data = $_COOKIE['session_data'];
$obj = unserialize($data);

// 不安全：反序列化外部來源資料
$payload = file_get_contents('php://input');
$result = unserialize($payload);

// 不安全：反序列化資料庫中的資料
$row = $stmt->fetch();
$config = unserialize($row['settings']);
