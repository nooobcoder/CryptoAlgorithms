using System.Configuration;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    public static readonly string Key = ConfigurationManager.AppSettings["Encryption_Key"];
    public static readonly Encoding Encoder = Encoding.UTF8;

    #region Encryptor Util Function(s)
    public static TripleDES CreateDes(string key)
    {
        MD5 md5 = MD5.Create();
        TripleDES des = TripleDES.Create();
        var desKey = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
        des.Key = desKey;
        des.IV = new byte[des.BlockSize / 8];
        des.Padding = PaddingMode.PKCS7;
        des.Mode = CipherMode.ECB;
        return des;
    }
    #endregion

    public static string TripleDesEncrypt(string plainText)
    {
        var des = CreateDes(Key);
        var ct = des.CreateEncryptor();
        var input = Encoding.UTF8.GetBytes(plainText);
        var output = ct.TransformFinalBlock(input, 0, input.Length);
        return Convert.ToBase64String(output);
    }

    public static string TripleDesDecrypt(string cypherText)
    {
        var des = CreateDes(Key);
        var ct = des.CreateDecryptor();
        var input = Convert.FromBase64String(cypherText);
        var output = ct.TransformFinalBlock(input, 0, input.Length);
        return Encoding.UTF8.GetString(output);
    }

    public static string ByteArrayToHexString(byte[] ba)
    {
        return BitConverter.ToString(ba).Replace("-", " ");
    }

    static void Main()
    {
        string message = "This is a super secret message.";
        string encrypted = TripleDesEncrypt(message);
        string encryptedBytes = ByteArrayToHexString(Encoding.UTF8.GetBytes(encrypted));
        string decrypted = TripleDesDecrypt(encrypted);
        Console.WriteLine($"Original Message: {message}" +
            $"\n\tEncrypted Message: {encrypted}" +
            $"\n\tEncrypted Bytes: {encryptedBytes}" +
            $"\n\tDecypted Message: {decrypted}");
    }
}
