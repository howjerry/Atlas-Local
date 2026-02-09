// Insecure Random: SHOULD trigger the rule
// Pattern: new Random() object creation
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System;

public class InsecureRandomFail
{
    public string GenerateToken()
    {
        var rng = new Random();
        var bytes = new byte[32];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)rng.Next(256);
        }
        return Convert.ToBase64String(bytes);
    }

    public int GenerateSessionId()
    {
        var random = new Random(42);
        return random.Next();
    }
}
