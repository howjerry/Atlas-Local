// Insecure TLS: SHOULD trigger the rule
// Pattern: 使用已棄用的 TLS/SSL 協定版本
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Net;

public class UnsafeTls
{
    public void UnsafeProtocol()
    {
        // 不安全：使用 TLS 1.0
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
    }

    public void UnsafeSsl3()
    {
        // 不安全：使用 SSL 3.0
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
    }
}

