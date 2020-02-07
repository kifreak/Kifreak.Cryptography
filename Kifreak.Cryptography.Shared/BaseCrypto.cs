using System;
using System.Text;
using System.Linq;

namespace Kifreak.Cryptography { 
    public class BaseCrypto
    {
        private static readonly Random _rmd = new Random();
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

        protected string GetString(byte[] byteElement)
        {
            return GetString(byteElement, byteElement.Length);
        }

        protected string GetString(byte[] byteElement, int count)
        {
            return Encoding.UTF8.GetString(byteElement, 0, count);
        }
        public static string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[_rmd.Next(s.Length)]).ToArray());
        }
       
    }
}