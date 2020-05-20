using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DotnetCity.Cryptography
{
    public interface ICrypto
    {
        string Encrypt(string plainText, string key, string iv);
        string Decrypt(string cipherText, string key, string iv);
    }
    public class Crypto : ICrypto
    {
        public string Encrypt(string plainText, string key, string iv)
        {
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                MD5CryptoServiceProvider hashMD5 = new MD5CryptoServiceProvider();
                rijAlg.Key = hashMD5.ComputeHash(Encoding.ASCII.GetBytes(key));
                rijAlg.IV = hashMD5.ComputeHash(Encoding.ASCII.GetBytes(iv));
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return ByteArrayToHexString(encrypted).ToUpper();
        }

        public string Decrypt(string cipherText, string key, string iv)
        {
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                MD5CryptoServiceProvider hashMD5 = new MD5CryptoServiceProvider();
                rijAlg.Key = hashMD5.ComputeHash(Encoding.ASCII.GetBytes(key));
                rijAlg.IV = hashMD5.ComputeHash(Encoding.ASCII.GetBytes(iv));
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                byte[] bytes = HexStringToByteArray(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        private static string ByteArrayToHexString(byte[] byteArray)
        {
            string result = string.Empty;
            foreach (byte outputByte in byteArray)
            {
                result += outputByte.ToString("x2");
            }
            return result;
        }

        private static byte[] HexStringToByteArray(string hexString)
        {
            int stringLength = hexString.Length;
            byte[] bytes = new byte[stringLength / 2];
            for (int i = 0; i < stringLength; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}