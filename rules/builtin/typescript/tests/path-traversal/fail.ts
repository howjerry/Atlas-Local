// Path Traversal: SHOULD trigger the rule
// Pattern: fs method call with template string argument
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import * as fs from "fs";

const filename = req.params.file;

const data1 = fs.readFileSync(`/uploads/${filename}`);

fs.writeFile(`./data/${filename}`, content, callback);

const stream = fs.createReadStream(`${baseDir}/${userPath}`);

fs.unlink(`/tmp/${req.query.name}`, callback);
