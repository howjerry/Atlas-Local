// Log Injection: SHOULD trigger the rule
// Pattern: ILogger 使用字串內插記錄未清理的使用者輸入
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using Microsoft.Extensions.Logging;

public class UnsafeLogging
{
    private readonly ILogger _logger;

    public void UnsafeLogInfo(string username)
    {
        // 不安全：使用字串內插
        _logger.LogInformation($"User login: {username}");
    }

    public void UnsafeLogError(string errorMsg)
    {
        // 不安全：使用字串內插記錄錯誤
        _logger.LogError($"Error occurred: {errorMsg}");
    }

    public void UnsafeConsole(string input)
    {
        // 不安全：Console.WriteLine 使用字串內插
        Console.WriteLine($"Received input: {input}");
    }
}

