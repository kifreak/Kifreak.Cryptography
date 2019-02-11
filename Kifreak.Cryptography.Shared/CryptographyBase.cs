using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Kifreak.Cryptography
{
    //TODO - PasswordDeriveBytes.GetBytes Obsolete --> Investigate Rfc2898DeriveBytes
    public class CryptographyBase<T> where T : SymmetricAlgorithm, new()
    {
        private readonly int _iterations = 2;
        private readonly int _keySize = 256;
        private static readonly Random _rmd = new Random();
        private readonly string _hash = "SHA256";

        protected T Algorithm;
        protected byte[] VectorBytes;
        protected byte[] SaltBytes;
        protected byte[] KeyBytes;
        protected MemoryStream MemoryStream;
        protected CryptoStream CryptoStream;

        protected string Salt { get; set; }
        protected string Vector { get; set; }

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

        protected byte[] GetBytes(string message)
        {
            return Encoding.UTF8.GetBytes(message);
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

        private void Init(string password)
        {
            Algorithm = new T
            {
                Mode = CipherMode.CBC
            };
            VectorBytes = GetBytes(Vector);
            SaltBytes = GetBytes(Salt);
            PasswordDeriveBytes passwordBytes = new PasswordDeriveBytes(password, SaltBytes, _hash, _iterations);
            KeyBytes = passwordBytes.GetBytes(_keySize / 8);
            MemoryStream = new MemoryStream();
        }

        private static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[_rmd.Next(s.Length)]).ToArray());
        }
    }
}