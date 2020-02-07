namespace Kifreak.Cryptography.Asymmetric
{
    public class Decrypt: CryptographyBase, IDecrypt
    {

        public Decrypt(string privateKey)
        {
            Rsa.ToXmlString(true);
            Rsa.FromXmlString(privateKey);

        }
        public string DecryptMessage(string encryptedMessage)
        {
            return DecryptMessage(GetFromBase64(encryptedMessage));

        }

        public string DecryptMessage(byte[] byteMessage)
        {
            return GetString(DecryptByteMessage(byteMessage, out int count), count);
        }

        public byte[] DecryptByteMessage(byte[] byteMessage, out int count)
        {
            byte[] decrypted = Rsa.Decrypt(byteMessage, false);
            count = decrypted.Length;
            return decrypted;
        }
    }
}