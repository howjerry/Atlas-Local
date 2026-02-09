<?php
// 安全：使用 json_decode 解析資料
$data = json_decode($jsonString, true);

// 安全：使用 callable 陣列做動態調度
$handlers = [
    'add' => fn($a, $b) => $a + $b,
    'sub' => fn($a, $b) => $a - $b,
];
$result = $handlers[$action]($x, $y);

// 安全：使用 match 表達式
$result = match($operation) {
    'add' => $a + $b,
    'sub' => $a - $b,
    default => throw new InvalidArgumentException('Unknown operation'),
};
