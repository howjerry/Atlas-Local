<?php
// 不安全：使用變數作為重導向 URL
$url = $_GET['redirect'];
header("Location: $url");

// 不安全：使用字串串接組合重導向
header("Location: " . $returnUrl);

// 不安全：直接傳入變數
header($redirectHeader);
