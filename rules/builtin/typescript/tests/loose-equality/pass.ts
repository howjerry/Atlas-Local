function checkValue(x: string | null) {
    if (x === null) {
        return "empty";
    }
    if (x !== "") {
        return "non-empty";
    }
}

const isEqual = (a: number, b: number) => a === b;
