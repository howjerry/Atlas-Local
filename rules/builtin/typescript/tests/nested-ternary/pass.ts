// Nested Ternary: should NOT trigger the rule
// Uses simple ternary or if-else

const a = true;

// 簡單的三元運算式（未巢狀）
const x = a ? 1 : 2;

// 使用 if-else 取代巢狀三元
let status: string;
if (isAdmin) {
  status = "admin";
} else if (isMod) {
  status = "moderator";
} else {
  status = "user";
}

// 使用函式抽象化邏輯
function getLabel(value: number): string {
  if (value > 100) return "high";
  if (value > 50) return "medium";
  return "low";
}
