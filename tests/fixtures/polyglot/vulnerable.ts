// TypeScript file with known vulnerabilities for polyglot testing.
// NOTE: This file INTENTIONALLY contains insecure patterns for SAST test fixtures.

export async function getUser(db: any, userId: string) {
  // SQL injection via template string -- should trigger atlas/security/typescript/sql-injection
  const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
  return result.rows[0];
}

export function renderProfile(el: HTMLElement, userHtml: string) {
  // XSS via innerHTML -- INTENTIONAL VULNERABILITY for SAST test fixture
  // nosec: test fixture - not production code
  el.innerHTML = userHtml;
}
