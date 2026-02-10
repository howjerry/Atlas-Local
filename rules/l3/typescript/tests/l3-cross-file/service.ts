// L3 跨檔案污染：service 接收未淨化的輸入並直接傳入 db.query
// 注意：此為 SAST 偵測用測試夾具
export function findUser(username) {
    const sql = "SELECT * FROM users WHERE name = '" + username + "'";
    return db.query(sql);
}
