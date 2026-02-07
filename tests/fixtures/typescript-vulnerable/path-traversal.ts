import * as fs from 'fs';
import * as path from 'path';

export function readUserFile(filename: string) {
  const filePath = path.join('/uploads', filename);
  return fs.readFileSync(filePath, 'utf-8');
}

export function serveFile(userPath: string) {
  const content = fs.readFileSync('/var/www/' + userPath);
  return content;
}
