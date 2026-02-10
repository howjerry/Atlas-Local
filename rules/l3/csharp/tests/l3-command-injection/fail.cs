// L3 Command Injection: 跨方法污染 — Request.QueryString → arg → Process.Start
// 注意：此為 SAST 偵測用測試夾具
public class AdminController
{
    public void Execute()
    {
        var cmd = Request.QueryString["cmd"];
        RunProcess(cmd);
    }

    void RunProcess(string command)
    {
        Process.Start(command);
    }
}
