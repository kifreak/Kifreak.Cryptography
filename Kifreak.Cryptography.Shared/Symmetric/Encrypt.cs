using System;
using System.Security.Cryptography;


namespace Kifreak.Cryptography.Symmetric
{
    public class Encrypt : CryptographyBase<AesManaged>,IEncrypt
    {
        public Encrypt(string password, string salt, string vector) : base(password, salt, vector)
        {
        }
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
            if (string.IsNullOrEmpty(message))
            {
                throw new Exception("Message not found");
            }
            return EncryptMessageToByte(GetBytes(message));
        }

        public byte[] EncryptMessage(byte[] byteMessage)
        {
            CryptoStream = new CryptoStream(MemoryStream, CreateEncryptor(), CryptoStreamMode.Write);
            CryptoStream.Write(byteMessage, 0, byteMessage.Length);
            CryptoStream.FlushFinalBlock();
            byte[] encrypted = MemoryStream.ToArray();
            return encrypted;
        }
    }
}