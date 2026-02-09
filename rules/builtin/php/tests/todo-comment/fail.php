<?php
// TODO: 實作使用者認證邏輯
function authenticate($user) {
    return true;
}

// FIXME: 這個查詢在大資料量時效能很差
function getUsers() {
    return $db->query("SELECT * FROM users");
}

// HACK: 暫時繞過快取問題
$cache->clear();

/* XXX: 需要重構這段程式碼 */
function processData($data) {
    return $data;
}
