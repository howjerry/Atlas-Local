// Code Injection via use of dynamic code execution: should NOT trigger the rule
// Uses safe alternatives instead of dynamic code execution

const userCode = req.body.expression;

const parsed = JSON.parse(userCode);

const value = obj[propertyName];

const result = new Map([["add", (a: number, b: number) => a + b]]);
const fn = result.get("add");
