using System.Security.Cryptography;

namespace Kifreak.Cryptography
{
    public class Encrypt : CryptographyBase<AesManaged>
    {

        public Encrypt(string password) : base(password)
        {
            
            
        }

        public string EncryptMessageToByte(byte[] messageByte)
        {
            byte[] encryptedMessage = EncryptMessage(messageByte);
            return GetBase64(encryptedMessage);
        }

        public string EncryptMessage(string message)
        {
            return EncryptMessageToByte(GetBytes(message));
        }

        public byte[] EncryptMessage(byte[] byteMessage)
        {
            CryptoStream = new CryptoStream(MemoryStream, GetEncryptor(), CryptoStreamMode.Write);
            CryptoStream.Write(byteMessage, 0, byteMessage.Length);
            CryptoStream.FlushFinalBlock();
            byte[] encrypted = MemoryStream.ToArray();
            return encrypted;
        }
    }


    //public class Encrypt : CryptographyBase
    //{
    //    public Encrypt(string password) : base(password)
    //    {
    //        _cryptoStream = new CryptoStream(_memoryStream,
    //            _aes.CreateEncryptor(_key, _iv),
    //            CryptoStreamMode.Write);
    //    }


    //    public string EncryptTextToString(string message)
    //    {
    //        return ConvertToString(EncryptTextToByte(message));
    //    }

    //    public byte[] EncryptTextToByte(string message)
    //    {
    //        byte[] plainMessageBytes = GetBytesFromString(message);
    //        return EncryptBytes(plainMessageBytes);
    //    }

    //    //public byte[] EncryptFile(byte[] file)
    //    //{
    //    //    return EncryptBytes(file);
    //    //}

    //    //public byte[] EncryptFile(string filePath)
    //    //{
    //    //    return EncryptFile(File.ReadAllBytes(filePath));
    //    //}

    //    //public void EncryptAndSaveFile(string filePath, string pathToSave, string fileName)
    //    //{
    //    //    byte[] encryptedFile = EncryptFile(filePath);
    //    //    FileStream fs = File.Create(pathToSave + "\\" + fileName, 2048, FileOptions.None);
    //    //    BinaryWriter writer = new BinaryWriter(fs);
    //    //    writer.Write(encryptedFile);
    //    //    writer.Close();
    //    //}

    //    public string ConvertToString(byte[] encryptedMessage)
    //    {
    //        return Convert.ToBase64String(encryptedMessage);
    //    }

    //    public byte[] EncryptBytes(byte[] plainMessageBytes) {
    //        _cryptoStream = new CryptoStream(_memoryStream, _aes.CreateEncryptor(), CryptoStreamMode.Write);
    //        _cryptoStream.Write(plainMessageBytes, 0, plainMessageBytes.Length);
    //        var result =  _memoryStream.ToArray();
    //        Dispose();
    //        return result;
    //    }

    //    public byte[] EncryptBytes(string plainMessage)
    //    {
           
    //        _cryptoStream = new CryptoStream(_memoryStream, _aes.CreateEncryptor(), CryptoStreamMode.Write);
    //        StreamWriter writer = new StreamWriter(_cryptoStream);
    //        writer.Write(plainMessage);
    //        byte[] result = _memoryStream.ToArray();
    //        Dispose();
    //        return result;
    //    }
    //}
}
