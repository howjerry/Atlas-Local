import { Logger } from "./logger";

function logUser(user: string) {
    const logger = new Logger();
    logger.info("User data:", user);
}

function processData(data: string): string {
    return data.toUpperCase();
}
