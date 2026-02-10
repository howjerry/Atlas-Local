# Log Injection: should NOT trigger the rule
# 使用硬編碼字串或結構化日誌

# 安全：使用硬編碼字串
logger.info("Application started")

# 安全：使用 block 形式
logger.info { "Processing request" }

