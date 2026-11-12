using System.Security.Cryptography;

// MD5.Create() was replaced by SHA-256.
public static class Hashing
{
    public static byte[] Digest(byte[] data) => SHA256.HashData(data);

    public static AesGcm Cipher(byte[] key) => new AesGcm(key, 16);
}
