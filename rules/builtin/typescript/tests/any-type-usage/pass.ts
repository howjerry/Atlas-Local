function processData(input: unknown): string {
    if (typeof input === "string") {
        return input;
    }
    return String(input);
}

const value: string = "typed";

function genericExample<T>(input: T): T {
    return input;
}
