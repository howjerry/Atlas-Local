<?php
// 良好：拋出例外代替 exit
if (!$authenticated) {
    throw new AuthenticationException('Not authenticated');
}

// 良好：回傳錯誤狀態
function handleRequest() {
    if ($error) {
        return new Response('Error', 500);
    }
    return new Response('OK', 200);
}

// 良好：使用 return 終止函式
function process() {
    if (!$valid) {
        return false;
    }
    return true;
}
