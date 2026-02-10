// CORS Wildcard: should NOT trigger the rule
// 使用特定的 origin 白名單

import cors from "cors";
import express from "express";

const app = express();

// 安全：指定特定的 origin
app.use(cors({ origin: "https://app.example.com" }));

// 安全：使用 origin 陣列
app.use(cors({ origin: ["https://app.example.com", "https://admin.example.com"] }));

// 安全：使用回呼函數動態驗證
app.use(cors({
  origin: (origin, callback) => {
    const allowlist = ["https://app.example.com"];
    if (!origin || allowlist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  }
}));

