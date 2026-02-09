// Prototype Pollution: should NOT trigger the rule
// Uses safe object merging patterns

import { z } from "zod";

// 使用展開運算子搭配已知屬性
const config = { ...defaults, name: input.name, age: input.age };

// 使用 schema 驗證
const userSchema = z.object({
  name: z.string(),
  email: z.string().email(),
});
const validated = userSchema.parse(requestBody);

// 使用 structuredClone 進行深拷貝
const cloned = structuredClone(source);

// 手動挑選屬性
function mergeOptions(opts: Record<string, unknown>) {
  return {
    timeout: typeof opts.timeout === "number" ? opts.timeout : 5000,
    retries: typeof opts.retries === "number" ? opts.retries : 3,
  };
}
