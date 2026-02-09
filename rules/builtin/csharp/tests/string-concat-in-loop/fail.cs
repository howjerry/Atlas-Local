// String Concat in Loop: SHOULD trigger the rule
// Pattern: += operator inside for/while/foreach/do-while loops

using System;
using System.Collections.Generic;

public class StringConcatInLoopFail
{
    public string BuildCsv(List<string> items)
    {
        string result = "";
        foreach (var item in items)
        {
            result += item + ",";
        }
        return result;
    }

    public string BuildReport(int count)
    {
        string output = "";
        for (int i = 0; i < count; i++)
        {
            output += "Line " + i + "\n";
        }
        return output;
    }

    public string ReadAll(Queue<string> queue)
    {
        string text = "";
        while (queue.Count > 0)
        {
            text += queue.Dequeue();
        }
        return text;
    }
}
