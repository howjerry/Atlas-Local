<?php
// Unrestricted File Upload: SHOULD trigger the rule
// Pattern: move_uploaded_file 未經驗證直接搬移上傳檔案
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

// 不安全：直接搬移上傳檔案，無任何驗證
$tmpFile = $_FILES['avatar']['tmp_name'];
$destPath = 'uploads/' . $_FILES['avatar']['name'];
move_uploaded_file($tmpFile, $destPath);

// 不安全：使用變數路徑
move_uploaded_file($_FILES['document']['tmp_name'], $uploadDir . $filename);

