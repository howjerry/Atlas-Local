// L3 Command Injection (safe): 使用靜態字串
public class AdminController
{
    public void Execute()
    {
        var cmd = "notepad.exe";
        RunProcess(cmd);
    }

    void RunProcess(string command)
    {
        Process.Start(command);
    }
}
