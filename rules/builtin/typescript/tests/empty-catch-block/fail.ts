function riskyOperation() {
    try {
        JSON.parse("invalid");
    } catch (e) { }
}

function anotherRisky() {
    try {
        fetch("/api/data");
    } catch (error) {
    }
}
