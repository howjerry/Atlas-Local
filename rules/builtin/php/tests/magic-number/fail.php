<?php
// 不良：魔術數字（意義不明的常數）
if ($retries > 3) {
    throw new Exception('Too many retries');
}

// 不良：計算中使用魔術數字
$price = $quantity * 19;

// 不良：條件中使用魔術數字
if ($age >= 18) {
    $allowed = true;
}

// 不良：超時設定使用魔術數字
$timeout = $base + 30;
