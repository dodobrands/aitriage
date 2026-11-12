using System.Security.Cryptography;
using System.Text;

public static class Hashing
{
    public static byte[] PasswordHash(string password)
    {
        // ruleid: ASP-WEAK-CRYPTO
        using var md5 = MD5.Create();
        return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
    }
}
