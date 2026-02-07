// Code Injection via Function constructor: should NOT trigger the rule
// Uses static function definitions instead of dynamic construction

function add(a: number, b: number): number {
  return a + b;
}

const handlers: Record<string, () => void> = {
  greet: () => console.log("hello"),
  farewell: () => console.log("goodbye"),
};

const handler = handlers[action];
