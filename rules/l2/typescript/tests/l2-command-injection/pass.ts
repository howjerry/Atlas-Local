function handler(req) {
    const cmd = req.body.command;
    const safe = sanitize(cmd);
    console.log(safe);
}
