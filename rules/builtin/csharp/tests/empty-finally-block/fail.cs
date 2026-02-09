// Empty Finally Block: SHOULD trigger the rule
// Pattern: finally clause with empty block

using System;

public class EmptyFinallyBlockFail
{
    public void ProcessData()
    {
        try
        {
            Console.WriteLine("Processing...");
        }
        finally
        {
        }
    }

    public void ReadFile()
    {
        var stream = System.IO.File.OpenRead("data.txt");
        try
        {
            var buffer = new byte[1024];
            stream.Read(buffer, 0, buffer.Length);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
        }
        finally { }
    }
}
