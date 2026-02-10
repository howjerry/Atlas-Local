// Log Injection: should NOT trigger the rule
// 使用結構化日誌模板

using Microsoft.Extensions.Logging;

public class SafeLogging
{
    private readonly ILogger _logger;

    public void SafeLogInfo(string username)
    {
        // 安全：使用結構化日誌模板
        _logger.LogInformation("User login: {Username}", username);
    }

    public void SafeLogError(string errorMsg)
    {
        // 安全：使用結構化日誌模板
        _logger.LogError("Error occurred: {ErrorMessage}", errorMsg);
    }
}

