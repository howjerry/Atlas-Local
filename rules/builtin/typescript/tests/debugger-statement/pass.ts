// Debugger Statement: should NOT trigger the rule
// Uses proper logging and error handling instead

import { Logger } from "./logger";

const logger = new Logger();

function processData(data: unknown) {
  logger.debug("Processing data", { data });
  return transform(data);
}

function handleError(error: Error) {
  logger.error("Error occurred", { error: error.message });
  throw error;
}

// 使用斷言取代 debugger
function validateInput(input: string) {
  if (input.length === 0) {
    throw new Error("Input cannot be empty");
  }
}
