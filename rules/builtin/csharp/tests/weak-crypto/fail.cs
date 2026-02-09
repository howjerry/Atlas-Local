// Weak Crypto: SHOULD trigger the rule
// Pattern: MD5.Create(), SHA1.Create(), DES.Create()
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Security.Cryptography;

public class WeakCryptoFail
{
    public byte[] HashWithMD5(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    public byte[] HashWithSHA1(byte[] data)
    {
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
    }

    public byte[] EncryptWithDES(byte[] data)
    {
        using var des = DES.Create();
        return des.Key;
    }
}
