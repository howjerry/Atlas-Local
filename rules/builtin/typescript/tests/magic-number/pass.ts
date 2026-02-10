// Magic Number: should NOT trigger the rule
// Uses named constants or small common values

// 使用命名常數
const MAX_RETRIES = 300;
if (retries > MAX_RETRIES) {
  stopRetrying();
}

// 常見的小數值不觸發（< 100）
const index = array.length - 1;
const half = total / 2;
const isEmpty = count === 0;

// 使用列舉常數
const SECONDS_PER_DAY = 86400;
const SESSION_TIMEOUT = SECONDS_PER_DAY;

// 常數宣告本身不是 binary_expression
const TAX_RATE = 108;

// HTTP status codes 不應觸發
if (response.status === 200) {
  handleSuccess();
}
if (response.status === 404) {
  handleNotFound();
}
