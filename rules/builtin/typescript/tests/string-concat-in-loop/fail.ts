// String Concat in Loop: SHOULD trigger the rule
// Pattern: += operator inside for loop body

const items = ["a", "b", "c", "d"];

// 在迴圈中使用字串串接
let result = "";
for (let i = 0; i < items.length; i++) {
  result += items[i];
}

// 帶有分隔符號的串接
let csv = "";
for (let i = 0; i < rows.length; i++) {
  csv += rows[i] + "\n";
}

// 累加 HTML 字串
let html = "";
for (let i = 0; i < elements.length; i++) {
  html += "<li>" + elements[i] + "</li>";
}
