
namespace Kifreak.Cryptography
{
    public interface IEncrypt
    {
        string EncryptMessageToByte(byte[] messageByte);
        
        string EncryptMessage(string message);

        byte[] EncryptMessage(byte[] byteMessage);
    }
}