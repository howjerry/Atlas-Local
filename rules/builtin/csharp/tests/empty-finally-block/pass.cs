// Empty Finally Block: should NOT trigger the rule
// Finally blocks contain cleanup logic

using System;

public class EmptyFinallyBlockPass
{
    public void ProcessData()
    {
        var stream = System.IO.File.OpenRead("data.txt");
        try
        {
            var buffer = new byte[1024];
            stream.Read(buffer, 0, buffer.Length);
        }
        finally
        {
            stream.Dispose();
        }
    }

    public void WithUsing()
    {
        // 使用 using 語句自動管理資源，不需要 finally
        using var stream = System.IO.File.OpenRead("data.txt");
        var buffer = new byte[1024];
        stream.Read(buffer, 0, buffer.Length);
    }
}
