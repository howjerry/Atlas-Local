// Regex DoS: should NOT trigger the rule
// 使用帶 timeout 的 Regex 或 GeneratedRegex

using System.Text.RegularExpressions;

public class SafeRegex
{
    public bool SafeMatch(string input)
    {
        // 安全：指定 timeout
        var regex = new Regex("^(a+)+$", RegexOptions.None, TimeSpan.FromSeconds(1));
        return regex.IsMatch(input);
    }

    // 安全：使用靜態方法
    public bool SafeStaticMatch(string input)
    {
        return Regex.IsMatch(input, "^[a-z]+$", RegexOptions.None, TimeSpan.FromSeconds(1));
    }
}

