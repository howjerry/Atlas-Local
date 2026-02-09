<?php
// 不良：使用 exit 終止程式
if (!$authenticated) {
    exit(1);
}

// 不良：使用 die 終止程式
if ($error) {
    die("Fatal error occurred");
}

// 不良：在控制器中使用 exit
function handleRequest() {
    exit(0);
}
