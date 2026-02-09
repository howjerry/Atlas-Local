<?php
// 不安全：使用變數作為檔案路徑
$path = $_GET['file'];
$content = file_get_contents($path);

// 不安全：使用字串插值組合路徑
$data = file_get_contents("/uploads/$filename");

// 不安全：fopen 使用變數
$handle = fopen($userPath, "r");

// 不安全：readfile 使用使用者輸入
readfile($requestedFile);

// 不安全：file_put_contents 使用變數路徑
file_put_contents($outputPath, $data);
