// Open Redirect: SHOULD trigger the rule
// Pattern: window.location.assign() or window.location.replace() calls

const userInput = new URLSearchParams(window.location.search).get("redirect");

// 使用 assign 進行重新導向
window.location.assign(userInput!);

// 使用 replace 進行重新導向
window.location.replace(userInput!);

// 透過 document.location 進行重新導向
document.location.assign(redirectUrl);

// 使用變數呼叫
function redirect(url: string) {
  window.location.replace(url);
}
