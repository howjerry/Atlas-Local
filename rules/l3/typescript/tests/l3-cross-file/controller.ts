// L3 跨檔案污染：controller 從 req.body 取得使用者輸入，
// 透過 import 的 service 函數傳遞到 db.query sink
// 注意：此為 SAST 偵測用測試夾具
import { findUser } from "./service";

function handleRequest(req, res) {
    const name = req.body.name;
    const user = findUser(name);
    res.json(user);
}
