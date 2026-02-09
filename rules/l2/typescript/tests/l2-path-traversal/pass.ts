function handler(req) {
    const filePath = req.body.path;
    const safePath = path.normalize(filePath);
    fs.readFile(safePath);
}
