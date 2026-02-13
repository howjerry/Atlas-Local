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

// 安全：Request headers 不是 Response header injection
function setupRequest(headers: Headers, token: string) {
  headers.set('authorization', token);
}

// 安全：MMKV 本地儲存
function saveToStorage(mmkv: MMKV, key: string, value: string) {
  mmkv.set(key, value);
}

// 安全：一般本地儲存
function saveData(storage: AsyncStorage, key: string, value: string) {
  storage.set(key, value);
}

