// Insecure TLS: should NOT trigger the rule
// 使用安全的 TLS 1.2/1.3

using System.Net;

public class SafeTls
{
    public void SafeProtocol()
    {
        // 安全：使用 TLS 1.2 和 TLS 1.3
        ServicePointManager.SecurityProtocol =
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
    }
}

