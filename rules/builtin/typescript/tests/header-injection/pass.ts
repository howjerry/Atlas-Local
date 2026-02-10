// Header Injection: should NOT trigger the rule
// 使用硬編碼的 header 值

import { Request, Response } from "express";

function handleRequest(req: Request, res: Response) {
  // 安全：硬編碼的 header 值
  res.setHeader("Content-Type", "application/json");

  // 安全：使用常數
  res.set("X-Frame-Options", "DENY");

  // 安全：硬編碼的 Cache-Control
  res.header("Cache-Control", "no-store, no-cache, must-revalidate");

  // 安全：使用硬編碼的 status code + headers
  res.writeHead(200, "OK");
}

