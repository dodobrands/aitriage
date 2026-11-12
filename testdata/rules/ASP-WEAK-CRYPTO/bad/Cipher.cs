using System.Security.Cryptography;

public static class Cipher
{
    public static Aes Create(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;
        // ruleid: ASP-WEAK-CRYPTO
        aes.Mode = CipherMode.ECB;
        return aes;
    }
}
