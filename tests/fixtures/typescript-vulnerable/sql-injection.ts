import { db } from './db';

export function getUserById(userId: string) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return db.query(query);
}

export function searchUsers(name: string) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
