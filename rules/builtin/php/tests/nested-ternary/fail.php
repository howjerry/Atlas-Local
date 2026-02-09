<?php
// 不良：巢狀三元運算子
$result = $a > 0 ? ($b > 0 ? 'both positive' : 'a positive') : 'a not positive';

// 不良：另一個巢狀三元運算子
$label = $score >= 90 ? 'A' : ($score >= 80 ? 'B' : 'C');

// 不良：在賦值中使用巢狀三元
$status = $active ? ($verified ? 'active-verified' : 'active-unverified') : 'inactive';
