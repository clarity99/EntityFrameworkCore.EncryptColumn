using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using EntityFrameworkCore.EncryptColumn.Interfaces;

namespace EntityFrameworkCore.EncryptColumn.Util
{
    public class GenerateEncryptionProvider : IEncryptionProvider
    {
        private readonly string key;
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        public GenerateEncryptionProvider(string key)
        {
            this.key = key;
        }

        public string Encrypt(string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(key) || key=="nokey")
                throw new ArgumentNullException("EncryptionKey", "Please initialize your encryption key.");

            if (string.IsNullOrEmpty(dataToEncrypt))
                return string.Empty;

            byte[] iv = new byte[16];
            rng.GetBytes(iv);
            byte[] salt = new byte[16];
            rng.GetBytes(salt);
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new())
                {
                    //Write salt and IV to stream prior to encryption - ST
                    memoryStream.Write(salt, 0, salt.Length);
                    memoryStream.Write(iv, 0, iv.Length);

                    //1234 is considered our pepper - the hard-coded number of mutations to use - ST
                    using Rfc2898DeriveBytes pdb = new(key, salt, 10000, HashAlgorithmName.SHA512);

                    aes.Key = pdb.GetBytes(32);
                    aes.IV = iv;
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (CryptoStream cryptoStream = new((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new((Stream)cryptoStream))
                        {
                            streamWriter.Write(dataToEncrypt);
                        }
                        array = memoryStream.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(array);
        }

        public string Decrypt(string dataToDecrypt)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("EncryptionKey", "Please initialize your encryption key.");

            if (string.IsNullOrEmpty(dataToDecrypt))
                return string.Empty;

            byte[] iv = new byte[16];
            byte[] salt = new byte[16];
            try
            {
                using (Aes aes = Aes.Create())
                {
                    var buffer = Convert.FromBase64String(dataToDecrypt);
                    using (MemoryStream memoryStream = new(buffer))
                    {
                        memoryStream.Read(salt, 0, salt.Length);
                        memoryStream.Read(iv, 0, iv.Length);

                        //1234 is considered our pepper - the hard-coded number of mutations to use - ST
                        using Rfc2898DeriveBytes pdb = new(key, salt, 10000, HashAlgorithmName.SHA512);

                        aes.Key = pdb.GetBytes(32);
                        aes.IV = iv;
                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                        using (CryptoStream cryptoStream = new((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader streamReader = new((Stream)cryptoStream))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            } catch (Exception ex)
            {
                return "Error in decryption";
            }

        }
    }
}