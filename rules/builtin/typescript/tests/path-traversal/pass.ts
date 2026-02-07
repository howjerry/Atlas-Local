// Path Traversal: should NOT trigger the rule
// Uses validated paths or static strings

import * as fs from "fs";
import * as path from "path";

const safePath = path.resolve(baseDir, userInput);
if (!safePath.startsWith(baseDir)) {
  throw new Error("Path traversal detected");
}

const data = fs.readFileSync(safePath);

fs.readFileSync("/etc/config/app.json");

fs.writeFile(path.join(__dirname, "output.txt"), content, callback);
