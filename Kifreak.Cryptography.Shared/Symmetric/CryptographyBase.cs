using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Kifreak.Cryptography.Symmetric
{
    public class CryptographyBase<T>: BaseCrypto where T : SymmetricAlgorithm, new()
    {
        private readonly int _iterations = 2;
        private readonly int _keySize = 256;
       
        private readonly string _hash = "SHA256";

        protected T Algorithm;
        protected byte[] VectorBytes;
        protected byte[] SaltBytes;
        protected byte[] KeyBytes;
        protected MemoryStream MemoryStream;
        protected CryptoStream CryptoStream;

        public string Salt { get; private set; }
        public string Vector { get; private set; }

        public CryptographyBase(string password) : this(password, RandomString(16), RandomString(16))
        {
        }

        public CryptographyBase(string password, string salt, string vector)
        {
            Salt = salt;
            Vector = vector;
            Init(password);
        }

        protected ICryptoTransform CreateEncryptor()
        {
            return Algorithm.CreateEncryptor(KeyBytes, VectorBytes);
        }

        protected ICryptoTransform CreateDecryptor()
        {
            return Algorithm.CreateDecryptor(KeyBytes, VectorBytes);
        }

       

        private void Init(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new Exception("Password not found");
            }

            Algorithm = new T
            {
                Mode = CipherMode.CBC
            };

            VectorBytes = GetBytes(Vector);
            SaltBytes = GetBytes(Salt);
            Rfc2898DeriveBytes passwordBytes = new Rfc2898DeriveBytes(password,SaltBytes, _iterations);
            KeyBytes = passwordBytes.GetBytes(_keySize / 8);
            MemoryStream = new MemoryStream();
        }

     
    }

   
}