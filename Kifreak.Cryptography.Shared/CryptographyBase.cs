using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Kifreak.Cryptography
{
    public class CryptographyBase<T> where T : SymmetricAlgorithm, new()
    {
        protected int Iterations = 2;
        protected int KeySize = 256;

        protected string Hash = "SHA256";
        protected string Salt = "aselrias38490a32"; // Random??
        protected string Vector = "8947az34awl34kjq"; // Random??
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
            VectorBytes = GetBytes(Vector);
            SaltBytes = GetBytes(Salt);
            PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, SaltBytes, Hash, Iterations);
            KeyBytes = passwordBytes.GetBytes(KeySize / 8);
            MemoryStream = new MemoryStream();
        }

        public byte[] GetBytes(string message)
        {
            return Encoding.UTF8.GetBytes(message);
        }

        public ICryptoTransform GetEncryptor()
        {
            return Algorithm.CreateEncryptor(KeyBytes, VectorBytes);
        }

        public ICryptoTransform GetDecryptor()
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