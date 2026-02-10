// L3 Command Injection: 跨函數污染 — req.body → arg → fs.readFile (path traversal variant)
// 注意：此為 SAST 偵測用測試夾具，故意包含不安全模式
function handleUpload(req, res) {
    const filePath = req.body.path;
    readUserFile(filePath);
}

function readUserFile(path) {
    fs.readFile(path);
}
