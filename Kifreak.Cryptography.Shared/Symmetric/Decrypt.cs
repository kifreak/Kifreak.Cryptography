using System.IO;
using System.Security.Cryptography;

namespace Kifreak.Cryptography.Symmetric
{
    public class Decrypt : CryptographyBase<AesManaged>, IDecrypt
    {
        public Decrypt(string password, string salt, string vector) : base(password, salt, vector) { }

        public Decrypt(string password) : base(password)
        {
        }

        public string DecryptMessage(string encryptedMessage)
        {
            return DecryptMessage(GetFromBase64(encryptedMessage));
        }

        public string DecryptMessage(byte[] byteMessage)
        {
            return GetString(DecryptByteMessage(byteMessage, out var count), count);
        }

        public byte[] DecryptByteMessage(byte[] byteMessage, out int count)
        {
            byte[] decrypted = new byte[byteMessage.Length];
            MemoryStream = new MemoryStream(byteMessage);
            CryptoStream = new CryptoStream(MemoryStream, CreateDecryptor(), CryptoStreamMode.Read);
            try
            {
                count = CryptoStream.Read(decrypted, 0, decrypted.Length);
            }
            catch
            {
                count = 0;
                return new byte[0];
            }

            return decrypted;
        }
    }
}