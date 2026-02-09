// String Concat in Loop: should NOT trigger the rule
// Uses Array.join() or map() instead of loop concatenation

const items = ["a", "b", "c", "d"];

// 使用 Array.join() 串接
const result = items.join("");

// 使用 map + join 產生 CSV
const csv = rows.map((row) => row.join(",")).join("\n");

// 使用 map + join 產生 HTML
const html = elements.map((el) => `<li>${el}</li>`).join("");

// 使用 reduce（非 for 迴圈）
const summary = data.reduce((acc, item) => acc + item.name, "");
