// NoSQL Injection: SHOULD trigger the rule
// Pattern: MongoDB 查詢方法使用變數或模板字串
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import { MongoClient } from "mongodb";

async function findUser(db: any, userInput: any) {
  // 不安全：直接使用使用者輸入作為查詢條件
  const user = await db.collection("users").findOne(userInput);

  // 不安全：find 使用變數
  const results = await db.collection("orders").find(userInput);

  // 不安全：updateOne 使用變數
  await db.collection("users").updateOne(userInput, { $set: { active: true } });

  // 不安全：deleteMany 使用變數
  await db.collection("sessions").deleteMany(userInput);
}

