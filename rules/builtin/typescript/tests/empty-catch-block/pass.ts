function safeOperation() {
    const data = JSON.parse('{"valid": true}');
    return data;
}

function properErrorHandling() {
    try {
        JSON.parse("invalid");
    } catch (e) {
        console.error("Parse failed:", e);
    }
}
