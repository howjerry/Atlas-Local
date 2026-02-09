// Empty Conditional: should NOT trigger the rule
// If blocks contain actual logic

const condition = true;

// 有實作邏輯的 if 區塊
if (condition) {
  doSomething();
}

// 帶有 guard clause
if (!isValid) {
  throw new Error("Invalid input");
}

// 有回傳值的條件
function process(data: unknown): string {
  if (data !== null) {
    return String(data);
  }
  return "default";
}
