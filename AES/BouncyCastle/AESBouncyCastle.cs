using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace AES.BouncyCastle
{
    // Implementing the AES encryption algorithm using Bouncy Castle library.
    public class AESBouncyCastle
    {
        private const string ALGORITHM = "AES";

        private const byte AesIvSize = 16;
        private const byte GcmTagSize = 16;

        private readonly CipherMode _cipherMode;
        private readonly PaddingMode _padding;

        private readonly string _algorithm;

        public AESBouncyCastle(CipherMode cipherMode = CipherMode.CBC, PaddingMode padding = PaddingMode.None)
        {
            _cipherMode = cipherMode;
            _padding = padding;
            _algorithm = $"{ALGORITHM}/{_cipherMode}/{_padding}";
        }

        private ICipherParameters CreateKeyParameters(byte[] key, byte[] iv, int macSize)
        {
            var keyParameter = new KeyParameter(key);
            if (_cipherMode == CipherMode.CBC)
            {
                return new ParametersWithIV(keyParameter, iv);
            }

            throw new Exception("Unsupported cipher mode");
        }

        private string PackCipherData(byte[] encryptedBytes, byte[] iv)
        {
            var dataSize = encryptedBytes.Length + iv.Length + 1;

            var index = 0;
            var data = new byte[dataSize];
            data[index] = AesIvSize;
            index += 1;

            Array.Copy(iv, 0, data, index, iv.Length);
            index += iv.Length;
            Array.Copy(encryptedBytes, 0, data, index, encryptedBytes.Length);

            return Convert.ToBase64String(data);
        }

        private (byte[], byte[], byte) UnpackCipherData(string cipherText)
        {
            var index = 0;
            var cipherData = Convert.FromBase64String(cipherText);
            byte ivSize = cipherData[index];
            index += 1;

            byte tagSize = 0;

            byte[] iv = new byte[ivSize];
            Array.Copy(cipherData, index, iv, 0, ivSize);
            index += ivSize;

            byte[] encryptedBytes = new byte[cipherData.Length - index];
            Array.Copy(cipherData, index, encryptedBytes, 0, encryptedBytes.Length);
            return (encryptedBytes, iv, tagSize);
        }

        public string Encrypt(string plainText, byte[] key)
        {
            var random = new SecureRandom();
            var iv = random.GenerateSeed(AesIvSize);
            var keyParameters = CreateKeyParameters(key, iv, GcmTagSize * 8);
            var cipher = CipherUtilities.GetCipher(_algorithm);
            cipher.Init(true, keyParameters);

            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            var cipherText = cipher.DoFinal(plainTextBytes);

            return PackCipherData(plainTextBytes, iv);
        }

        public string Decrypt(string cipherText, byte[] key)
        {
            var (encryptedBytes, iv, tagSize) = UnpackCipherData(cipherText);
            var keyParameters = CreateKeyParameters(key, iv, tagSize * 8);
            var cipher = CipherUtilities.GetCipher(_algorithm);
            cipher.Init(false, keyParameters);

            var decryptedData = cipher.DoFinal(encryptedBytes);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
