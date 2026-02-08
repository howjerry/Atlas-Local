// Command Injection: SHOULD trigger the rule
// Pattern: Process.Start() and new ProcessStartInfo() with user input
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Diagnostics;

public class CommandInjectionFail
{
    public void UnsafeProcessStart(string userInput)
    {
        Process.Start(userInput);

        var info = new ProcessStartInfo(userInput);
        Process.Start(userInput, "--flag");
    }
}
