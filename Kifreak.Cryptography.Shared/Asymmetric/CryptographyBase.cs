using System.Security.Cryptography;

namespace Kifreak.Cryptography.Asymmetric
{
    public class CryptographyBase: BaseCrypto
    {
        protected RSACryptoServiceProvider Rsa;
        public CryptographyBase()
        {
            Rsa = new RSACryptoServiceProvider();
        }

        
    }
}