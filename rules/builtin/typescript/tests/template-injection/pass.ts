// Template Injection: should NOT trigger the rule
// 使用硬編碼的模板或檔案路徑

import ejs from "ejs";
import pug from "pug";

function renderSafe(req: any, res: any) {
  // 安全：使用硬編碼的模板字串
  const html = ejs.render("<h1><%= name %></h1>", { name: req.body.name });

  // 安全：從檔案載入模板
  const pugFn = pug.compileFile("./views/index.pug");

  // 安全：使用 Express 的 res.render（從 views 目錄載入）
  res.render("profile", { user: req.user });
}

