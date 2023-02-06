using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashAES256demo
{
    public class Aes256HexClass
    {
        private readonly static string Hashkey = "DwXdAHiD4iUPRz4uzygd1E0mqbBenzvy";
        private readonly static string HashIV = "00000000000000000000000000000000";

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public string Encrypt(string data)
        {
            byte[] byt_encrypted;
            string str_encrypted = string.Empty;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.Key = Encoding.UTF8.GetBytes(Hashkey);
                    aes.IV = StringToByteArray(HashIV);

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(data);
                            }
                            byt_encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                //convert to hex
                str_encrypted = BitConverter.ToString(byt_encrypted).Replace("-", string.Empty);
            }
            catch (Exception ex)
            {

            }

            return str_encrypted;
        }

        public string Decrypt(string data)
        {
            string str_decrypted = string.Empty;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    aes.Key = Encoding.UTF8.GetBytes(Hashkey);
                    aes.IV = StringToByteArray(HashIV);

                    ICryptoTransform encryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (MemoryStream ms = new MemoryStream(StringToByteArray(data)))
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader sr = new StreamReader(cs, Encoding.UTF8))
                            {
                                str_decrypted = sr.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {

            }

            return str_decrypted;
        }
    }
}
