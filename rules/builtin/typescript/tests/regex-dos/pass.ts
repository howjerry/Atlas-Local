// ReDoS: should NOT trigger the rule
// Uses hardcoded regex patterns or regex literals

// 使用正規表達式字面值
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// 使用硬編碼字串建構 RegExp
const phoneRegex = new RegExp("^\\d{3}-\\d{3}-\\d{4}$");

// 使用字面值字串
const dateRegex = new RegExp("^\\d{4}-\\d{2}-\\d{2}$", "i");

// 使用 includes 取代正規表達式搜尋
function search(items: string[], query: string): string[] {
  return items.filter((item) => item.toLowerCase().includes(query.toLowerCase()));
}
