// Command Injection: should NOT trigger the rule
// Uses fixed commands with validated arguments

using System.Diagnostics;

public class CommandInjectionPass
{
    public void SafeProcessStart()
    {
        var info = new ProcessStartInfo();
        info.FileName = "/usr/bin/git";
        info.Arguments = "status";
        info.UseShellExecute = false;
        info.RedirectStandardOutput = true;

        var process = new Process();
        process.StartInfo = info;
        process.Start();
    }
}
