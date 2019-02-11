using Xunit;

namespace Kifreak.Cryptography.UnitTest
{
    [Trait("Category", "Basic")]
    public class EncryptTest
    {
        private readonly string _pass = "IamUsingaLongPasswordToUsethisService";

        [Fact]
        public void EncryptMessage()
        {
            string salt = "12345678abcdefgh";
            string vector = "abcdefgh12345678";
            Encrypt encrypt = new Encrypt(_pass, salt, vector);
            Decrypt decrypt = new Decrypt(_pass, salt, vector);
            string originalMessage = "This is a test message to encrypt";
            string encrypted = encrypt.EncryptMessage(originalMessage);
            string decrypted = decrypt.DecryptMessage(encrypted);
            Assert.Equal(decrypted, originalMessage);
        }
    }
}