function handler(req) {
    const filePath = req.body.path;
    fs.readFile(filePath);
}
