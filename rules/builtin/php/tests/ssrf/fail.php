<?php
// 不安全：使用使用者輸入的 URL 取得內容
$url = $_GET['url'];
$content = file_get_contents($url);

// 不安全：fopen 使用使用者提供的 URL
$handle = fopen($url, "r");

// 不安全：curl_setopt 設定使用者輸入的 URL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
