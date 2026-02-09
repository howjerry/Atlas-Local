<?php
// 不良：使用 @ 抑制錯誤
$value = @file_get_contents('missing.txt');

// 不良：抑制除法錯誤
$result = @($a / $b);

// 不良：抑制物件方法呼叫的錯誤
$data = @$obj->riskyMethod();

// 不良：抑制陣列存取錯誤
$item = @$array['missing_key'];
