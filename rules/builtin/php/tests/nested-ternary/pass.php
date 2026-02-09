<?php
// 良好：使用 if-else 替代巢狀三元
if ($a > 0) {
    $result = $b > 0 ? 'both positive' : 'a positive';
} else {
    $result = 'a not positive';
}

// 良好：使用 match 表達式（PHP 8.0+）
$label = match(true) {
    $score >= 90 => 'A',
    $score >= 80 => 'B',
    default => 'C',
};

// 良好：單層三元運算子（可讀性良好）
$status = $active ? 'active' : 'inactive';
