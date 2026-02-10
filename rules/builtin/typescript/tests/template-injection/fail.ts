// Template Injection: SHOULD trigger the rule
// Pattern: 模板引擎使用變數作為模板內容
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import ejs from "ejs";
import pug from "pug";
import nunjucks from "nunjucks";

function renderUserTemplate(req: any, res: any) {
  const userTemplate = req.body.template;

  // 不安全：EJS compile 使用變數
  const fn = ejs.compile(userTemplate);

  // 不安全：EJS render 使用變數
  const html = ejs.render(userTemplate, { name: "user" });

  // 不安全：Pug compile 使用變數
  const pugFn = pug.compile(userTemplate);

  // 不安全：Nunjucks renderString 使用模板字串
  const output = nunjucks.renderString(`Hello ${req.body.name}`);
}

