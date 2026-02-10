// NoSQL Injection: should NOT trigger the rule
// 使用硬編碼的查詢物件

import { MongoClient, ObjectId } from "mongodb";

async function findUser(db: any, userId: string) {
  // 安全：使用明確的欄位和型別轉換
  const user = await db.collection("users").findOne({ _id: new ObjectId(userId) });

  // 安全：硬編碼的查詢條件
  const admins = await db.collection("users").find({ role: "admin" });

  // 安全：使用物件字面量
  await db.collection("users").updateOne(
    { email: "admin@example.com" },
    { $set: { lastLogin: new Date() } }
  );

  // 安全：countDocuments 使用硬編碼條件
  const count = await db.collection("logs").countDocuments({ level: "error" });
}

