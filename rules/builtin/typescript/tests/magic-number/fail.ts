// Magic Number: SHOULD trigger the rule
// Pattern: numeric literal >= 100 in binary expressions

// 在比較中使用魔術數字
if (retries > 300) {
  stopRetrying();
}

// 在計算中使用魔術數字
const total = price * 108;

// 用於超時判斷
if (elapsed >= 86400) {
  expireSession();
}

// 在條件中使用
const isOverLimit = count > 1000;
