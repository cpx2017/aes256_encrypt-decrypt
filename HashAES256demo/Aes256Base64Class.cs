using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace HashAES256demo
{
    public class Aes256Base64Class
    {
        private readonly static string Hashkey = "J/oGT57kMv41cXwnfymePakCwQJQWnuHtk5yNn52BYo=";
        private readonly static string HashIV = "NICHRKgKQixG1ALAWt4KXQ==";

        public class BaseDataResponse<T> : BaseDataResponse
        {
            public T OnSuccess { get; set; }

        }

        public class BaseDataResponse
        {
            public bool IsSuccess { get; set; } = false;

            public FailModel OnFail { get; set; } = new FailModel()
            {
                Description = "ไม่สามารถทำรายการได้ เนื่องจากระบบขัดข้อง กรุณาลองใหม่ภายหลัง",
            };

            public class FailModel
            {
                public string Description { get; set; }
            }
        }
        public class ResponsePlainText
        {
            public string PlainText { get; set; }
        }

        public class ResponseGenerateKey
        {
            public string Key { get; set; }
            public string IV { get; set; }
        }

        public class DecryptString : ResponseGenerateKey
        {
            public string PlainText { get; set; }
        }

        public class EncryptString : DecryptString
        {
            public bool EncodeBase64 { get; set; }
        }



        public string Decrypt(string input)
        {
            BaseDataResponse<ResponsePlainText> result = new BaseDataResponse<ResponsePlainText>();

            string decryptstr = "";

            try
            {
                string strdecrypt = DecryptQueryString(input, Hashkey, HashIV);

                if (!string.IsNullOrEmpty(strdecrypt))
                {
                    decryptstr = strdecrypt;
                }
            }
            catch
            {

            }

            return decryptstr;
        }

        public string Encrypt(string plainText)
        {
            string encryptText = string.Empty;

            try
            {
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Hashkey == null || Hashkey.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (HashIV == null || HashIV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;

                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.KeySize = 256;
                    //aesAlg.GenerateIV();
                    //byte[] iv = aesAlg.IV;
                    //string ivAsBase64 = Convert.ToBase64String(iv);

                    //aesAlg.Key = Encoding.ASCII.GetBytes(Key);
                    aesAlg.Key = Convert.FromBase64String(Hashkey);
                    aesAlg.IV = Convert.FromBase64String(HashIV);
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

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

                encryptText = Base64UrlEncoder.Encode(Convert.ToBase64String(encrypted));

                return encryptText;
            }
            catch
            {
                throw new ArgumentNullException("cannot decrypt text.");
            }
        }

        private static string DecryptQueryString(string plainText, string key, string vi)
        {
            string result = string.Empty;

            try
            {
                #region AES256


                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (key == null || key.Length <= 0)
                    throw new ArgumentNullException("key");
                if (vi == null || vi.Length <= 0)
                    throw new ArgumentNullException("vi");

                byte[] encrypted;

                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.KeySize = 256;
                    //aesAlg.GenerateIV();
                    //byte[] iv = aesAlg.IV;
                    //string ivAsBase64 = Convert.ToBase64String(iv);

                    aesAlg.Key = Encoding.ASCII.GetBytes(key);
                    aesAlg.IV = System.Convert.FromBase64String(vi);
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

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

                result = Base64UrlEncoder.Encode(Convert.ToBase64String(encrypted));


                #endregion
            }
            catch
            {
                #region Base64Decode

                try
                {
                    byte[] buffer2 = Convert.FromBase64String(Base64UrlEncoder.Decode(plainText));
                    //PasswordDeriveBytes bytes2 = new PasswordDeriveBytes(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(vi));
                    using (RijndaelManaged managed = new RijndaelManaged())
                    {
                        managed.Mode = CipherMode.CBC;
                        managed.Padding = PaddingMode.PKCS7;
                        using (ICryptoTransform transform = managed.CreateDecryptor(Convert.FromBase64String(key), Convert.FromBase64String(vi)))
                        {
                            using (MemoryStream stream = new MemoryStream(buffer2))
                            {
                                using (CryptoStream stream2 = new CryptoStream((Stream)stream, transform, (CryptoStreamMode)CryptoStreamMode.Read))
                                {
                                    //byte[] buffer3 = new byte[buffer2.Length];
                                    //stream2.Read(buffer2, 0, buffer3.Length);
                                    //result = Encoding.UTF8.GetString(buffer3);

                                    using (StreamReader stream3 = new StreamReader(stream2))
                                    {
                                        result = stream3.ReadToEnd();
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                    try
                    {
                        #region HttpUtility

                        byte[] buffer2 = Convert.FromBase64String(HttpUtility.UrlDecode(plainText));
                        //PasswordDeriveBytes bytes2 = new PasswordDeriveBytes(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(vi));
                        using (RijndaelManaged managed = new RijndaelManaged())
                        {
                            managed.Mode = CipherMode.CBC;
                            managed.Padding = PaddingMode.PKCS7;
                            using (ICryptoTransform transform = managed.CreateDecryptor(Convert.FromBase64String(key), Convert.FromBase64String(vi)))
                            {
                                using (MemoryStream stream = new MemoryStream(buffer2))
                                {
                                    using (CryptoStream stream2 = new CryptoStream((Stream)stream, transform, (CryptoStreamMode)CryptoStreamMode.Read))
                                    {
                                        //byte[] buffer3 = new byte[buffer2.Length];
                                        //stream2.Read(buffer2, 0, buffer3.Length);
                                        //result = Encoding.UTF8.GetString(buffer3);

                                        using (StreamReader stream3 = new StreamReader(stream2))
                                        {
                                            result = stream3.ReadToEnd();
                                        }
                                    }
                                }
                            }
                        }
                        #endregion
                    }
                    catch
                    {
                        throw new ArgumentNullException("cannot decrypt text.");
                    }
                }
            }

            return result;

            #endregion
        }
    }
}
