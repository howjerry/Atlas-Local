import { db } from './db';

export function getUserById(userId: number) {
  const query = "SELECT * FROM users WHERE id = $1";
  return db.query(query, [userId]);
}

export function sanitizeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function setContent(text: string) {
  const el = document.getElementById('content');
  if (el) {
    el.textContent = text;
  }
}
