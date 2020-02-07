Easy library for encrypt-decrypt with symmetric and asymmetric keys

#Symmetric

- Use Kifreak.Cryptography.Symmetric namespace
- Example
```C#
Encrypt encrypt = new Encrypt("MyPass", "MySalt", "MyVector");
string encryptedText = encrypt.EncryptMessage("My Message to encrypt");
Decrypt decrypt = new Decrypt("MyPass", "MySalt", "MyVector");
string decrypted = decrypt.DecryptMessage(encrypted);
```
#Asymmetric
	- Use Kifreak.Cryptography.UnitTest namespace
	- Example
	```C#
	Encrypt encrypt = new Encrypt("MyPublicKey");
	string encryptedText = encrypt.EncryptMessage("My Message to encrypt");
	Decrypt decrypt = new Decrypt("MySecretKey");
	string decrypted = decrypt.DecryptMessage(encrypted);
	```
