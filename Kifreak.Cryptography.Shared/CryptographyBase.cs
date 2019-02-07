using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Kifreak.Cryptography
{
    //TODO - PasswordDeriveBytes.GetBytes Obsolete --> Investigate Rfc2898DeriveBytes
    public class CryptographyBase<T> where T : SymmetricAlgorithm, new()
    {
        private readonly int _iterations = 2;
        private readonly int _keySize = 256;

        private readonly string _hash = "SHA256";
        private readonly string _salt = "aselrias38490a32";
        private readonly string _vector = "8947az34awl34kjq";
        protected T Algorithm;
        protected byte[] VectorBytes;
        protected byte[] SaltBytes;
        protected byte[] KeyBytes;
        protected MemoryStream MemoryStream;
        protected CryptoStream CryptoStream;
        public CryptographyBase(string password)
        {
            Algorithm = new T
            {
                Mode = CipherMode.CBC
            };
            VectorBytes = GetBytes(_vector);
            SaltBytes = GetBytes(_salt);
            PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, SaltBytes, _hash, _iterations);
            KeyBytes = passwordBytes.GetBytes(_keySize / 8);
            MemoryStream = new MemoryStream();
        }

        protected byte[] GetBytes(string message)
        {
            return Encoding.UTF8.GetBytes(message);
        }

        protected ICryptoTransform GetEncryptor()
        {
            return Algorithm.CreateEncryptor(KeyBytes, VectorBytes);
        }

        protected ICryptoTransform GetDecryptor()
        {
            return Algorithm.CreateDecryptor(KeyBytes, VectorBytes);
        }

        protected string GetBase64(byte[] message)
        {
            return Convert.ToBase64String(message);
        }

        protected byte[] GetFromBase64(string message)
        {
            return Convert.FromBase64String(message);
        }

        protected string GetString(byte[] byteElement, int count)
        {
            return Encoding.UTF8.GetString(byteElement, 0, count);
        }
    }
}