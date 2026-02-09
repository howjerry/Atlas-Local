// Empty Conditional: SHOULD trigger the rule
// Pattern: if statements with empty body

const condition = true;

// 空的 if 區塊
if (condition) {
}

// 帶有 else 的空 if 區塊
if (isReady) {
} else {
  doSomething();
}

// 巢狀空 if
function process(data: unknown) {
  if (data !== null) {
  }
}
