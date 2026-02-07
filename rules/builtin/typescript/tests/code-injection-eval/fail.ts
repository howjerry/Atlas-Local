// Code Injection via eval(): SHOULD trigger the rule
// Pattern: call to eval() function
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

const userCode = req.body.expression;

const result1 = eval(userCode);

const result2 = eval("2 + " + userInput);

eval(JSON.stringify(config));
