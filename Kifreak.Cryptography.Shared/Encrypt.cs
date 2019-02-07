using System.Security.Cryptography;

namespace Kifreak.Cryptography
{
    public class Encrypt : CryptographyBase<AesManaged>
    {
        public Encrypt(string password) : base(password)
        {
        }

        public string EncryptMessageToByte(byte[] messageByte)
        {
            byte[] encryptedMessage = EncryptMessage(messageByte);
            return GetBase64(encryptedMessage);
        }

        public string EncryptMessage(string message)
        {
            return EncryptMessageToByte(GetBytes(message));
        }

        public byte[] EncryptMessage(byte[] byteMessage)
        {
            CryptoStream = new CryptoStream(MemoryStream, GetEncryptor(), CryptoStreamMode.Write);
            CryptoStream.Write(byteMessage, 0, byteMessage.Length);
            CryptoStream.FlushFinalBlock();
            byte[] encrypted = MemoryStream.ToArray();
            return encrypted;
        }
    }
}