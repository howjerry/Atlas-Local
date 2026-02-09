// String Concat in Loop: should NOT trigger the rule
// Uses StringBuilder or string.Join instead

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

public class StringConcatInLoopPass
{
    public string BuildCsv(List<string> items)
    {
        return string.Join(",", items);
    }

    public string BuildReport(int count)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < count; i++)
        {
            sb.Append("Line ").Append(i).Append('\n');
        }
        return sb.ToString();
    }

    public string ConcatOutsideLoop(string a, string b)
    {
        // 迴圈外的 += 不應觸發規則
        string result = "";
        result += a;
        result += b;
        return result;
    }
}
