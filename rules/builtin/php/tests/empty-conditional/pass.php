<?php
// 良好：有實作的 if 區塊
if ($condition) {
    handleCondition();
}

// 良好：有實作的 if-else 區塊
if ($status === 'active') {
    processUser($user);
} else {
    logInactiveUser($user);
}

// 良好：早期返回模式
if ($data === null) {
    return;
}
processData($data);
