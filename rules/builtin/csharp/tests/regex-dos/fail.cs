// Regex DoS: SHOULD trigger the rule
// Pattern: 建立 Regex 沒有指定 timeout
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Text.RegularExpressions;

public class UnsafeRegex
{
    public bool UnsafeMatch(string input)
    {
        // 不安全：沒有 timeout，可能被 ReDoS 攻擊
        var regex = new Regex("^(a+)+$");
        return regex.IsMatch(input);
    }

    public bool UnsafeEmailValidation(string email)
    {
        // 不安全：複雜的 regex 沒有 timeout
        var regex = new Regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        return regex.IsMatch(email);
    }
}

