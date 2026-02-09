<?php
// 不良：var_dump 留在程式碼中
var_dump($userData);

// 不良：在條件中使用 var_dump
if ($debug) {
    var_dump($response);
}

// 不良：var_dump 多個變數
var_dump($config);
