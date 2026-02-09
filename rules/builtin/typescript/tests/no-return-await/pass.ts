// No Return Await: should NOT trigger the rule
// Returns promise directly or uses await without return

// 直接回傳 promise（不使用 await）
async function fetchUser(id: string) {
  return getUserById(id);
}

// 使用 await 但不直接 return
async function processUser(id: string) {
  const user = await getUserById(id);
  return user.name;
}

// 在 try-catch 中使用 await（合理用法）
async function safeFetch(url: string) {
  try {
    const response = await fetch(url);
    return response.json();
  } catch (error) {
    return null;
  }
}
