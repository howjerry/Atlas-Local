<?php
// 良好：直接回傳條件結果
function isAdult($age) {
    return $age >= 18;
}

// 良好：直接回傳布林表達式
function isValid($data) {
    return !empty($data);
}

// 良好：回傳計算結果而非布林常數
function hasPermission($user, $resource) {
    return $user->role === 'admin' || in_array($resource, $user->permissions);
}
