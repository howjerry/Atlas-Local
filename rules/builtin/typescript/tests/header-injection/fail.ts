// Header Injection: SHOULD trigger the rule
// Pattern: res.setHeader/set/header/writeHead 使用變數作為 header 值
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import { Request, Response } from "express";

function handleRequest(req: Request, res: Response) {
  const userLang = req.query.lang as string;
  const redirectUrl = req.body.callback;

  // 不安全：setHeader 使用變數
  res.setHeader("Content-Language", userLang);

  // 不安全：set 使用變數
  res.set("Location", redirectUrl);

  // 不安全：使用模板字串
  res.header("X-Custom", `value-${req.query.custom}`);
}

