export function executeUserCode(code: string) {
  const result = eval(code);
  return result;
}

export function createFunction(body: string) {
  const fn = new Function('x', body);
  return fn(42);
}

export function dynamicEval(input: string) {
  return eval("(" + input + ")");
}
