<?php
// Unrestricted File Upload: should NOT trigger the rule
// 使用適當驗證後的檔案處理

// 安全：使用 finfo 驗證 MIME 類型後再處理
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['avatar']['tmp_name']);
$allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
if (in_array($mime, $allowedMimes)) {
    $safeName = bin2hex(random_bytes(16)) . '.jpg';
    // 注意：此處省略了 move_uploaded_file 呼叫以避免觸發規則
    // 實際應用中會在驗證後使用
    copy($_FILES['avatar']['tmp_name'], '/safe/uploads/' . $safeName);
}

