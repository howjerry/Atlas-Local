<?php
// 不良：print_r 留在程式碼中
print_r($userData);

// 不良：在偵錯區塊中使用 print_r
if ($debug) {
    print_r($config);
}

// 不良：print_r 輸出陣列
print_r($results);
