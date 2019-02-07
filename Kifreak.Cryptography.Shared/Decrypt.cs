using System.IO;
using System.Security.Cryptography;

namespace Kifreak.Cryptography
{
    public class Decrypt : CryptographyBase<AesManaged>
    {
        public Decrypt(string password) : base(password)
        {
        }

        public string DecryptMessage(string encryptedMessage)
        {
            byte[] valueBytes = GetFromBase64(encryptedMessage);
            return DecryptMessage(valueBytes);
        }

        public string DecryptMessage(byte[] byteMessage)
        {
            return GetString(DecryptByteMessage(byteMessage, out var count), count);
        }

        public byte[] DecryptByteMessage(byte[] byteMessage, out int count)
        {
            byte[] decrypted = new byte[byteMessage.Length];
            MemoryStream = new MemoryStream(byteMessage);
            CryptoStream = new CryptoStream(MemoryStream, GetDecryptor(), CryptoStreamMode.Read);
            count = CryptoStream.Read(decrypted, 0, decrypted.Length);
            return decrypted;
        }
    }
}