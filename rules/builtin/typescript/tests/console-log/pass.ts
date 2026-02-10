import { Logger } from "./logger";

function logUser(user: string) {
    const logger = new Logger();
    logger.info("User data:", user);
}

function processData(data: string): string {
    return data.toUpperCase();
}

// console.error 是正當的錯誤報告，不應觸發
function handleError(err: Error) {
    console.error("Operation failed:", err.message);
}
