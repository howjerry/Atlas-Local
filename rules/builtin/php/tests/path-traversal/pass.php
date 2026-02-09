<?php
// 安全：使用硬編碼路徑
$config = file_get_contents('/etc/app/config.json');

// 安全：使用 basename 去除目錄
$safeName = basename($userInput);

// 安全：使用 realpath 驗證路徑
$resolved = realpath($requestedFile);
if (strpos($resolved, '/var/www/uploads/') === 0) {
    // 路徑在允許的目錄內
}
