function handler(req) {
    const cmd = req.body.command;
    eval(cmd);
}
