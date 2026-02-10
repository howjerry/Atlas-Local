# Log Injection: SHOULD trigger the rule
# Pattern: Logger 使用字串內插記錄未清理的輸入
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

# 不安全：使用字串內插記錄使用者輸入
logger.info("User login: #{params[:username]}")

# 不安全：error 等級使用字串內插
logger.error("Failed auth for #{request.ip}: #{params[:user]}")

