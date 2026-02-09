// GitHub Token: SHOULD trigger the rule
// Pattern: string starting with ghp_, gho_, ghs_, ghu_, or github_pat_ followed by 20+ alphanumeric chars
// NOTE: 這些是 SAST 測試用假 token，不是真實 key

const token1 = "ghp_0000000000000000000000000000000000000000";

const token2 = "gho_0000000000000000000000000000000000000000";

const token3 = "github_pat_00000000000000000000000000000000000000000000";
