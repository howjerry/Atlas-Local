// L3 Command Injection (safe): 使用靜態字串，無外部輸入
function handleUpload(req, res) {
    const filePath = "/static/default.txt";
    readUserFile(filePath);
}

function readUserFile(path) {
    fs.readFile(path);
}
