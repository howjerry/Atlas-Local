// Insecure Random: should NOT trigger the rule
// Uses cryptographic random number generator

using System;
using System.Security.Cryptography;

public class InsecureRandomPass
{
    public string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes);
    }

    public int GenerateSessionId()
    {
        return RandomNumberGenerator.GetInt32(int.MaxValue);
    }
}
