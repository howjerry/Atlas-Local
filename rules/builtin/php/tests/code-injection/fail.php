<?php
// 不安全：動態程式碼執行（CWE-94）
$code = $_POST['code'];
eval($code);

// 不安全：動態組合字串後執行
eval('$result = ' . $expression . ';');

// 不安全：執行動態產生的程式碼
eval($dynamicCode);
