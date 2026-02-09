<?php
// 不安全：使用 md5 雜湊密碼
$hashedPassword = md5($password);

// 不安全：使用 sha1 雜湊
$token = sha1($secret);

// 不安全：使用 md5 做資料校驗
$checksum = md5($fileContents);
