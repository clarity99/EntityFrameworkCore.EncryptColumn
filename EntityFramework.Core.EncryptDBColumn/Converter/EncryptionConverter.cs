using EntityFrameworkCore.EncryptColumn.Interfaces;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace EntityFrameworkCore.EncryptColumn.Converter
{
    internal sealed class EncryptionConverter : ValueConverter<string, string>
    {
        public EncryptionConverter(IEncryptionProvider encryptionProvider, ConverterMappingHints mappingHints = null) : base (x => encryptionProvider.EncryptString(x), x => encryptionProvider.DecryptString(x), mappingHints)
        {
        }
    }

    internal sealed class EncryptionConverterByteArr : ValueConverter<byte[], byte[]>
    {
        public EncryptionConverterByteArr(IEncryptionProvider encryptionProvider, ConverterMappingHints mappingHints = null) : base(x => encryptionProvider.EncryptByteArr(x), x => encryptionProvider.DecryptByteArr(x), mappingHints)
        {
        }
    }
}
