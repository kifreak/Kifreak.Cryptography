using Xunit;

namespace Kifreak.Cryptography.UnitTest
{
    public class EncrypTest
    {
        private string _pass = "IamUsingaLongPasswordToUsethisService";

        [Fact]
        public void EncrypMessage()
        {
            Encrypt encrypt = new Encrypt(_pass);
            Decrypt decrypt = new Decrypt(_pass);
            string originalMessage = "This is a test message to encrypt";
            string encrypted = encrypt.EncryptMessage(originalMessage);
            string decrypted = decrypt.DecryptMessage(encrypted);
            Assert.Equal(decrypted, originalMessage);
        }
    }
}