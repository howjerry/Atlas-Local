// Alert Usage: SHOULD trigger the rule
// Pattern: alert() function calls

// 除錯用的 alert
alert("debug: reached this point");

// 顯示錯誤訊息
function handleError(msg: string) {
  alert("Error: " + msg);
}

// 確認刪除
function deleteItem(id: number) {
  alert("Item deleted: " + id);
}

// 在事件處理器中
document.getElementById("btn")?.addEventListener("click", () => {
  alert("Button clicked!");
});
