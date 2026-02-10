<?php
// Header Injection: SHOULD trigger the rule
// Pattern: header() 使用字串內插或串接包含變數
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

$lang = $_GET['lang'];

// 不安全：使用字串內插注入 header
header("Content-Language: $lang");

// 不安全：使用字串串接
header("X-Custom-Header: " . $_GET['value']);

// 不安全：重導向使用字串內插
header("Location: $redirectUrl");

