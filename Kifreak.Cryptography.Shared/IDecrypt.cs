namespace Kifreak.Cryptography
{
    public interface IDecrypt
    {
        string DecryptMessage(string encryptedMessage);
        string DecryptMessage(byte[] byteMessage);
        byte[] DecryptByteMessage(byte[] byteMessage, out int count);
    }
}