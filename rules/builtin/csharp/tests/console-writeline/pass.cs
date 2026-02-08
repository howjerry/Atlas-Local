using Microsoft.Extensions.Logging;

public class PassExample
{
    private readonly ILogger _logger;

    public PassExample(ILogger<PassExample> logger)
    {
        _logger = logger;
    }

    public void ProperLogging()
    {
        _logger.LogInformation("Processing started");
    }
}
