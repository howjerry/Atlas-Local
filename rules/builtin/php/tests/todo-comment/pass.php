<?php
// 已完成使用者認證邏輯
function authenticate($user) {
    return password_verify($user->password, $user->hash);
}

// 使用分頁查詢提升效能
function getUsers($page, $limit) {
    return $db->query("SELECT * FROM users LIMIT ? OFFSET ?", [$limit, $page * $limit]);
}

/* 快取管理已重構完成 */
function clearExpiredCache() {
    $cache->deleteExpired();
}
