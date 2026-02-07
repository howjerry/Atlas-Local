// Code Injection via Function constructor: SHOULD trigger the rule
// Pattern: new Function() expression
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

const userCode = req.body.code;

const fn1 = new Function(userCode);

const fn2 = new Function("a", "b", "return a + " + userCode);

const handler = new Function("event", dynamicBody);
