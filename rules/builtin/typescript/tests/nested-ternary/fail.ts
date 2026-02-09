// Nested Ternary: SHOULD trigger the rule
// Pattern: ternary expression inside another ternary expression

const a = true;
const b = false;

// 巢狀三元運算式
const x = a ? b ? 1 : 2 : 3;

// 巢狀在 alternative 分支
const y = a ? "yes" : b ? "maybe" : "no";

// 多層巢狀
const status = isAdmin ? "admin" : isMod ? "moderator" : "user";
