// Debugger Statement: SHOULD trigger the rule
// Pattern: debugger keyword usage

function processData(data: unknown) {
  // 開發時遺留的 debugger
  debugger;
  return transform(data);
}

function handleError(error: Error) {
  debugger;
  logError(error);
}

// 在條件內的 debugger
function validateInput(input: string) {
  if (input.length === 0) {
    debugger;
  }
}
