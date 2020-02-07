using System;
using System.Security.Cryptography;

namespace Kifreak.Cryptography.Tools
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("Kifreak Cryptography Tools");
            Line();
            Console.WriteLine("1. Generate Asymmetric Keys");
            Line();
            Console.Write("Select an option to continue: ");
            ConsoleKeyInfo key = Console.ReadKey();
            Console.WriteLine();
            
            switch (key.Key)
            {
                case ConsoleKey.D1:
                case ConsoleKey.NumPad1:
                    int size = GetKeySize();
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(size);
                    string publicKey = rsa.ToXmlString(false);
                    string privateKey = rsa.ToXmlString(true);
                    Line();
                    Line();
                    Console.WriteLine("Public Key (Share this key): ");
                    Console.WriteLine(publicKey);
                    Line();
                    Line();
                    Console.WriteLine("Private Key (DON'T SHARE. KEEP PRIVATE!!)");
                    Console.WriteLine(privateKey);
                    Line();
                    Line();
                    break;

            }

        }

        private static int GetKeySize()
        {
            Console.Write("Write the Size of the Key [3048]: ");
            var value = Console.ReadLine();
            if (string.IsNullOrEmpty(value))
            {
                return 3048;
            }

            if (int.TryParse(value, out int result))
            {
                return result;
            }
            else
            {
                return 3048;
            }
        }
        private static void Line()
        {
            Console.WriteLine("=============================================================");
        }
    }
}
