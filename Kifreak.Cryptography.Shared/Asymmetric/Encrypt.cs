namespace Kifreak.Cryptography.Asymmetric
{
    public class Encrypt : CryptographyBase, IEncrypt
    {
        
        public Encrypt(string publicKey)
        {
            Rsa.FromXmlString(publicKey);
        }
        
        public string EncryptMessageToByte(byte[] messageByte)
        {

            return  GetBase64(EncryptMessage(messageByte));
        }

        public string EncryptMessage(string message)
        {
            return EncryptMessageToByte(GetBytes(message));
        }

        public byte[] EncryptMessage(byte[] byteMessage)
        {
            return Rsa.Encrypt(byteMessage, false);
        }
    }
}