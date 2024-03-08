using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using EntityFrameworkCore.EncryptColumn.Interfaces;

namespace EntityFrameworkCore.EncryptColumn.Util
{
    public class GenerateEncryptionProvider : IEncryptionProvider
    {
        private readonly byte[] key;
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
        public GenerateEncryptionProvider(string key)
        {
            if (key == "nokey")
                throw new ArgumentNullException("EncryptionKey", "Please initialize your encryption key.");

            this.key = Convert.FromBase64String(key);
           
        }

        
        public string EncryptString(string dataToEncrypt)
        {
            if (string.IsNullOrEmpty(dataToEncrypt))
                return string.Empty;
            

            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToEncrypt);
            byte[] encryptedBytes = EncryptByteArr(dataBytes);

            return Convert.ToBase64String(encryptedBytes);
        }

        public byte[] EncryptByteArr(byte[] dataToEncrypt)
        {
            if (dataToEncrypt.Length == 0)
                return Array.Empty<byte>();
           

            byte[] iv = new byte[16];
            rng.GetBytes(iv);
            // byte[] salt = new byte[16];
            // rng.GetBytes(salt);
            byte[] encryptedData;

            using (Aes aes = Aes.Create())
            {
                using (MemoryStream memoryStream = new())
                {
                    //Write salt and IV to stream prior to encryption - ST
                    //memoryStream.Write(salt, 0, salt.Length);
                    memoryStream.Write(iv, 0, iv.Length);

                    //1234 is considered our pepper - the hard-coded number of mutations to use - ST
                    //using Rfc2898DeriveBytes pdb = new(key, salt, 10000, HashAlgorithmName.SHA512);
                    aes.Key = key;
                    aes.IV = iv;

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (CryptoStream cryptoStream = new((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    }

                    encryptedData = memoryStream.ToArray();
                }
            }

            return encryptedData;
        }

       

        public string DecryptString(string dataToDecrypt)
        {
            if (string.IsNullOrEmpty(dataToDecrypt))
                return string.Empty;

            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(dataToDecrypt);
                byte[] decryptedBytes = DecryptByteArr(encryptedBytes);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Error in decryption", ex);
            }
        }

        public byte[] DecryptByteArr(byte[] dataToDecrypt)
        {
            if (dataToDecrypt.Length == 0)
                return Array.Empty<byte>();

            byte[] iv = new byte[16];
            // byte[] salt = new byte[16];
            byte[] decryptedData;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    using (MemoryStream memoryStream = new(dataToDecrypt))
                    {
                        // memoryStream.Read(salt, 0, salt.Length);
                        memoryStream.Read(iv, 0, iv.Length);

                        //1234 is considered our pepper - the hard-coded number of mutations to use - ST
                        // using Rfc2898DeriveBytes pdb = new(key, salt, 10000, HashAlgorithmName.SHA512);
                        aes.Key = key;
                        aes.IV = iv;

                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                        using (CryptoStream cryptoStream = new((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (MemoryStream decryptedStream = new())
                            {
                                cryptoStream.CopyTo(decryptedStream);
                                decryptedData = decryptedStream.ToArray();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Error in decryption", ex);
                
            }

            return decryptedData;
        }
    }
}