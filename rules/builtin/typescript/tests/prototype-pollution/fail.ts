// Prototype Pollution: SHOULD trigger the rule
// Pattern: Object.assign() calls

const userInput = JSON.parse(requestBody);

// 直接將使用者輸入合併到目標物件
const config = Object.assign({}, defaults, userInput);

// 合併到現有物件
Object.assign(target, userInput);

// 深層合併可能導致 prototype pollution
const settings = Object.assign({}, baseSettings, req.body);

// 在函式中使用
function mergeOptions(opts: Record<string, unknown>) {
  return Object.assign({}, defaultOptions, opts);
}
