using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    class Program
    {
        static void Main()
        {
            // Generate AES key
            byte[] aesKey = GenerateAesKey();

            // Generate RSA key pair
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);

                // Convert RSA public key parameters to XML format for storage
                string publicKeyXml = ToXmlString(publicKey);

                // Write the RSA public key to a file
                string publicKeyFile = "public_key.xml";
                File.WriteAllText(publicKeyFile, publicKeyXml);
                Console.WriteLine("RSA public key generated and saved to file.");

                // Encrypt AES key using RSA public key
                byte[] encryptedAesKey = EncryptAesKeyWithRsa(aesKey, publicKeyXml);
                Console.WriteLine("AES key encrypted with RSA public key.");

                // Decrypt AES key using RSA private key
                byte[] decryptedAesKey = DecryptAesKeyWithRsa(encryptedAesKey, privateKey);
                Console.WriteLine("AES key decrypted with RSA private key.");

                // Encrypt text using AES key
                Console.Write("Enter the text to encrypt: ");
                string text = Console.ReadLine();
                byte[] encryptedText = EncryptText(text, decryptedAesKey);
                Console.WriteLine($"Text encrypted with AES key.");

                // Decrypt text using AES key
                string decryptedText = DecryptText(encryptedText, decryptedAesKey);
                Console.WriteLine($"Decrypted text: {decryptedText}");
            }
        }

        static byte[] GenerateAesKey()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                byte[] aesKey = aes.Key;
                return aesKey;
            }
        }

        static string ToXmlString(RSAParameters rsaParameters)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(rsaParameters);
                string publicKeyXml = rsa.ToXmlString(false);
                return publicKeyXml;
            }
        }

        static byte[] EncryptAesKeyWithRsa(byte[] aesKey, string publicKeyXml)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKeyXml);
                byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                return encryptedAesKey;
            }
        }

        static byte[] DecryptAesKeyWithRsa(byte[] encryptedAesKey, RSAParameters privateKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                byte[] decryptedAesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
                return decryptedAesKey;
            }
        }

        static byte[] EncryptText(string text, byte[] aesKey)
        {
            byte[] encryptedText;

            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.GenerateIV();
                byte[] iv = aes.IV;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(iv, 0, iv.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] textBytes = Encoding.UTF8.GetBytes(text);
                        cryptoStream.Write(textBytes, 0, textBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    encryptedText = memoryStream.ToArray();
                }
            }

            return encryptedText;
        }

        static string DecryptText(byte[] encryptedText, byte[] aesKey)
        {
            string decryptedText;

            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(encryptedText, iv, iv.Length);
                aes.IV = iv;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedText, iv.Length, encryptedText.Length - iv.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    decryptedText = Encoding.UTF8.GetString(memoryStream.ToArray());
                }
            }

            return decryptedText;
        }
    }
}