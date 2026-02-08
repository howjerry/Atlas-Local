// This function handles user input
function processData(input: string): string {
    return input.trim();
}

// Validates that the input is non-empty
function validate(input: string): boolean {
    return input.length > 0;
}

// Parses numeric string with fallback to zero
const result = parseInt(value, 10) || 0;
