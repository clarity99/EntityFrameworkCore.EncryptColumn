using System;
namespace EntityFrameworkCore.EncryptColumn.Interfaces
{
    public interface IEncryptionProvider
    {
        string EncryptString(string dataToEncrypt);
        string DecryptString(string dataToDecrypt);

        byte[] EncryptByteArr(byte[] dataToEncrypt);
        byte[] DecryptByteArr(byte[] dataToDecrypt);
    }
}
