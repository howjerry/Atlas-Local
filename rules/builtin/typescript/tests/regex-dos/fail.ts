// ReDoS: SHOULD trigger the rule
// Pattern: new RegExp() with dynamic (non-literal) input

const userPattern = req.query.pattern as string;

// 直接使用使用者輸入建構正規表達式
const regex1 = new RegExp(userPattern);

// 使用變數
const searchTerm = getSearchInput();
const regex2 = new RegExp(searchTerm, "gi");

// 使用 template string
const regex3 = new RegExp(`^${prefix}.*$`);

// 使用物件屬性
const regex4 = new RegExp(config.pattern);
