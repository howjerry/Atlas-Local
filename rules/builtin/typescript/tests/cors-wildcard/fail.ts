// CORS Wildcard: SHOULD trigger the rule
// Pattern: CORS 配置使用萬用字元 '*' 作為允許的 origin
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import cors from "cors";
import express from "express";

const app = express();

// 不安全：允許所有 origin
app.use(cors({ origin: "*" }));

// 不安全：在選項物件中設定 wildcard
const corsOptions = { origin: "*", credentials: true };
app.use(cors(corsOptions));

