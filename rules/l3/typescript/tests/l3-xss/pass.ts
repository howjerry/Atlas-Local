// L3 XSS (safe): 經過 escapeHtml 淨化後傳入
function handleSearch(req, res) {
    const term = escapeHtml(req.query.q);
    renderResult(res, term);
}

function renderResult(res, content) {
    res.send("<h1>" + content + "</h1>");
}
