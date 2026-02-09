// Alert Usage: should NOT trigger the rule
// Uses proper notification methods

import { toast } from "react-toastify";
import { Logger } from "./logger";

const logger = new Logger();

// 使用 toast 通知
function handleError(msg: string) {
  toast.error("Error: " + msg);
}

// 使用 logger
function deleteItem(id: number) {
  logger.info("Item deleted", { id });
}

// 使用自訂通知元件
function showNotification(message: string) {
  const notification = document.createElement("div");
  notification.className = "notification";
  notification.textContent = message;
  document.body.appendChild(notification);
}
