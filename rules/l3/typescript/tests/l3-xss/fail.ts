// L3 XSS: 跨函數污染 — req.query → arg → res.send
function handleSearch(req, res) {
    const term = req.query.q;
    renderResult(res, term);
}

function renderResult(res, content) {
    res.send("<h1>" + content + "</h1>");
}
