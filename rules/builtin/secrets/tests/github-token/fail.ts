// GitHub Token: SHOULD trigger the rule
// Pattern: string starting with ghp_, gho_, ghs_, ghu_, or github_pat_ followed by 20+ alphanumeric chars
// NOTE: This is a SAST test fixture with FAKE tokens that match the pattern

const token1 = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";

const token2 = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";

const token3 = "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd";
