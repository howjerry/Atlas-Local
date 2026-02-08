// TODO: refactor this function
function processData(input: string): string {
    return input;
}

// FIXME: this breaks when input is empty
function validate(input: string): boolean {
    return input.length > 0;
}

// HACK: workaround for upstream bug
const result = parseInt(value, 10) || 0;
