using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Kifreak.Cryptography.Symmetric;
using Xunit;
using Xunit.Abstractions;

namespace Kifreak.Cryptography.UnitTest
{
    [Trait("Category", "Basic")]
    public class SymmetricEncryptionTests
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string _pass = "IamUsingaLongPasswordToUsethisService";
        private readonly string _salt = "12345678abcdefgh";
        private readonly string _vector = "abcdefgh12345678";

        public SymmetricEncryptionTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void EncryptMessage()
        {
            Encrypt encrypt = new Encrypt(_pass, _salt, _vector);
            Decrypt decrypt = new Decrypt(_pass, _salt, _vector);
            string originalMessage = "This is a test message to encrypt";
            string encrypted = encrypt.EncryptMessage(originalMessage);
            string decrypted = decrypt.DecryptMessage(encrypted);
            Assert.Equal(decrypted, originalMessage);
        }

        [Fact]
        public void EncryptWithoutSaltAndVector()
        {
            Encrypt encrypt = new Encrypt(_pass);
            Decrypt decrypt = new Decrypt(_pass);
            string originalMessage = "This is a test message to encrypt";
            string encrypted = encrypt.EncryptMessage(originalMessage);
            string decrypted = decrypt.DecryptMessage(encrypted);
            Assert.NotEqual(decrypted, originalMessage);
            decrypt = new Decrypt(_pass, encrypt.Salt, encrypt.Vector);
            decrypted = decrypt.DecryptMessage(encrypted);
            Assert.Equal(decrypted, originalMessage);
        }

        [Fact]
        public void EncryptNullMessage()
        {
            Encrypt encrypt = new Encrypt(_pass, _salt, _vector);
            try
            {
                encrypt.EncryptMessage((string) null);
                Assert.True(false, "Must be provoke an exception");
            }
            catch (Exception ex)
            {
                Assert.Equal("Message not found", ex.Message);
            }
        }

        [Fact]
        public void EncryptNullPassword()
        {
            try
            {
                new CryptographyBase<AesManaged>(null);
                Assert.True(false, "Must be provoke an exception");
            }
            catch (Exception ex)
            {
                Assert.Equal("Password not found", ex.Message);
            }
        }

        [Fact]
        public void EncryptBigImage()
        {
            Encrypt encrypt = new Encrypt(_pass, _salt, _vector);
            Decrypt decrypt = new Decrypt(_pass, _salt, _vector);
            byte[] plutoImage = File.ReadAllBytes("files/pluto.tif");
            DateTime startDate = DateTime.Now;
            byte[] encrypted = encrypt.EncryptMessage(plutoImage);
            byte[] decrypted = decrypt.DecryptByteMessage(encrypted, out int count);
            DateTime endDate = DateTime.Now;
            TimeSpan totalTime = endDate - startDate;
            if (totalTime.TotalSeconds > 1)
            {
                Assert.True(false, "Must be decrypted in less than a 1000 milliseconds. Total milliseconds: " + totalTime.TotalMilliseconds);
            }
            _testOutputHelper.WriteLine("Total Milliseconds to encrypt and decrypt: " + totalTime.TotalMilliseconds);
            byte[] finalDecrypted = new byte[count];
            Array.Copy(decrypted, finalDecrypted, count);
            Assert.True(finalDecrypted.SequenceEqual(plutoImage));
        }

    }
}