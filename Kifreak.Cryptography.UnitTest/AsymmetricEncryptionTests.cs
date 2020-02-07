using Xunit;

namespace Kifreak.Cryptography.UnitTest
{
    [Trait("Category", "Basic")]
    public class AsymmetricEncryptionTests
    {
        private readonly string _privateKey =
            "<RSAKeyValue><Modulus>9tIdZxRlYGVJ2N12K+jqd3gXseoe9SLfzdeV7mUWuiDqbrvfA4NCyBtxDUNa1Fd7LBIiwMaaaiZ7DYRuncbG9nfTzcz5D+LAQ6twsajyQ/0CJwoMy3yGW9CYH/Sm6+AC8eQyNbJ5Sg8LC4r+S6X1UJMcj/ZOIPPSqnDB5QNatYPSbR9qyX52ZKMn73hl1p0F7lCREgFL4bZ7Dib6SMTDG7cMYaL+G62NXb4h4NSj2dTHWhjiEUw4eK809b6neCIhv/TYa2hWYs8OBr0yooaMnKfxIZY7ncUcYwGGz11+zoAwN2bD62IRUxvPGZHyjOM0Eb5lIH8UOoeUJP1m7+8MEipsAOU1nLaCrv3wzdazyck0t+lF7NdTnZflDPynp0RZUL6bsCrEn9SBYGps71sQdpQzt45v4vJBHekknJPML5WbXEvJHM2lRzd2Mf2Xtk+Q/uPeh9rnbwbjNiHXoJY+0iffDrzF7Xjc8UWRHpqfRBCDC0+BbAHW/iJWqlB55425</Modulus><Exponent>AQAB</Exponent><P>/XzwZg2cKAkarwGoAszLV1C1qsdzGSlaFtOzATLaCvYIwMLIKqNKViweXJ+3enSxptDQ0bhDjeDjBgwxdSHWnm5cEeaTf6Zpx0vXb4FmzIQvInak3PLTRD+oaHQ3S0dvWrikLlmbShOP4pWluftSc5rSbGSY34Zid6lzIslB3Mhbgh3KXR22aCqjcirGFEQMeqfptYKL5cDRFzy7VQzIWq/I14f2glRcCOjVQO3MLiZcQVOD80dE5avAW8U1pJXj</P><Q>+URDDGI9rIZRB2prp7A2PJu2zhYPctzi0ol7TSJfoF8Zbrs578DK0MEtTsizs3eMTEi3K/ESOVE6bj5NU4wvCidNBpVP7CFyxeRy7rImsbjeqwApTxeYRO6X+EMOCNNcxPo1NcIrjt/GUmZRjcXgjQWU/7t5u9cZvojso5V+0yhIVVwagqN2N+wnfC9kRVDkZE55usTkTqlvxzJQSMdj/6viwJSib3LdYtIZ5GYigAfG9CAuGLQwQ4On6n9jXkCz</Q><DP>nlmqI1ZlMm1die3S8szUSdtVYTXvJMy8Rn5A2ILXyvkfRqtnN5uCGIq+/MWZbJnxUHApwpkFOmA98c00KCPXWmk+gsAzbA6dDa7HChUgDqqUd0b+fjgC2iOaJIZU9GXPnjCx/3Jim8fUnos1WBUz0Jvqz2OYTCo64N2t2xE2X6GZ6JKLk9e31yKrr+ogixBna0fxqz29/uyQsZ9ytxKhJmWhZWK+D3R7eeVZMpJadonoH7b4OsVOuNqt86YieIpZ</DP><DQ>QecBTxHeOnHclHhXdCNLg6SrpTsB5J1vvrgoiFExNSZPhA4uGCxBswWP5Ad+M1HFHxoOi6iV59+I8kK4kQE8IpQXckkhs014mcd3d5JUVqKJBG7rfQTA9mCaf0HDQSQYn9+DF+55M7IILhrtLu2FG+PA7Af1/Gq3XL+4yNsqh8tbrG3IeIedJtXh7pxdB1KGv9pbpryNnBqB+glcXpGQ57TbI41okMyuqYTg4Zj7QBxORpcHePKS3Ba/22jIrc+v</DQ><InverseQ>WIpBtiV6U21AMDuTC/vfyF3hzQegKIN2php0b1OutjUL67QknelkhbKAGtlcTvt9UeyI2NAntE2Cr3owpngm0gUEP+PegUXJUOoZbDJiGa1eiqk2LxV1bdiYy4QY0Ep1C+2oVnoYh7bWf+ZqTsEFkZbG65T4/QMUJKssa0rmWrks2C2UMMYF93l/23wWx4A/0lb/nJ1p+SA6GUqQdc44rz0GQhQcbY3yYEhGURpIpyPNn/rsr9Lxq+5Kq4pKKK+k</InverseQ><D>EzzFNeeNDzpVyyVXtIxu2ejuT9ujlg+lyfFnqjEO2GsAWqkh9LAiYF5jLVl2lt5Kp2CyfLv+BRACv0b3KCz6DPPB+mRjdS2DNsMCAZbdaxcpN8m8vY9zGWzkrnjvGatYD2ptz2mdsnwBrGCk+VhyClms/DuCU2ctoEMxmZvtUgB4QjEUrafBqo5c6nlD1rpeX/i/ldusAmeqp6u6Djnnyx01RdbiX13jis7q7Q8lxjCjaQ5PcHG0ZROi2RSHEQH34EK6NP2JF7019XSdKU/1GjUjXdMn+Y4a9OwuScBPQzJz4YHuuU9SfE8Tx15NQsWU4UaQRcrLEUoz+gm3tneG/Guv1VWAJngzUqcotcLNlU3TKqrJUqml3RFu2E6AH2M5sfzso+j3Nq0OJFBzsyB29l6OKcLsWkvqHPVN2jRANS6ybBO/6lIyhTQypQ7z0ypomJR155yCynqy3Ir/A6gEsHml+TT6zJNH33yyqy8rTENcnNqJCz70GRjmI74ZRTpR</D></RSAKeyValue>";
        private readonly string _publicKey =
            "<RSAKeyValue><Modulus>9tIdZxRlYGVJ2N12K+jqd3gXseoe9SLfzdeV7mUWuiDqbrvfA4NCyBtxDUNa1Fd7LBIiwMaaaiZ7DYRuncbG9nfTzcz5D+LAQ6twsajyQ/0CJwoMy3yGW9CYH/Sm6+AC8eQyNbJ5Sg8LC4r+S6X1UJMcj/ZOIPPSqnDB5QNatYPSbR9qyX52ZKMn73hl1p0F7lCREgFL4bZ7Dib6SMTDG7cMYaL+G62NXb4h4NSj2dTHWhjiEUw4eK809b6neCIhv/TYa2hWYs8OBr0yooaMnKfxIZY7ncUcYwGGz11+zoAwN2bD62IRUxvPGZHyjOM0Eb5lIH8UOoeUJP1m7+8MEipsAOU1nLaCrv3wzdazyck0t+lF7NdTnZflDPynp0RZUL6bsCrEn9SBYGps71sQdpQzt45v4vJBHekknJPML5WbXEvJHM2lRzd2Mf2Xtk+Q/uPeh9rnbwbjNiHXoJY+0iffDrzF7Xjc8UWRHpqfRBCDC0+BbAHW/iJWqlB55425</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        
        [Fact]
        public void EncryptAndDecryptMessage()
        {
            string originalMessage = "This is a test message to encrypt";
            Asymmetric.Encrypt encrypt = new Asymmetric.Encrypt(_publicKey);
            string encrypted = encrypt.EncryptMessage(originalMessage);
            Asymmetric.Decrypt decrypt = new Asymmetric.Decrypt(_privateKey);
            string decrypted = decrypt.DecryptMessage(encrypted);
            Assert.Equal(originalMessage, decrypted);
        }
    }
}