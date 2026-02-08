function checkValue(x: string | number) {
    if (x == null) {
        return "empty";
    }
    if (x != 0) {
        return "non-zero";
    }
}

const isEqual = (a: number, b: string) => a == b;
