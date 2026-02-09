// Weak Crypto: should NOT trigger the rule
// Uses strong cryptographic algorithms

using System.Security.Cryptography;

public class WeakCryptoPass
{
    public byte[] HashWithSHA256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    public byte[] HashWithSHA512(byte[] data)
    {
        using var sha512 = SHA512.Create();
        return sha512.ComputeHash(data);
    }

    public byte[] EncryptWithAes(byte[] data)
    {
        using var aes = Aes.Create();
        return aes.Key;
    }
}
