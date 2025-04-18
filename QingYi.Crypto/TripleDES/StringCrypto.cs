using QingYi.Crypto.DES;
using System;
using System.Text;

namespace TripleDES
{
    /// <summary>
    /// 3DES string crypto. Based on the DES module of this library.<br></br>
    /// 3DES字符串加密。基于本库的DES模块。
    /// </summary>
    public class TripleDesStringCrypto
    {
        private readonly string Key;
        private readonly string IV;

        /// <summary>
        /// constructor<br></br>
        /// 构造函数
        /// </summary>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).|当key或IV不是正确的长度(8字节)时抛出。</exception>
        public TripleDesStringCrypto(string key, string iv)
        {
            if (key.Length != 24)
                throw new ArgumentException("Key must be 24 bytes long.");
            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes long.");

            Key = key;
            IV = iv;
        }

        /// <summary>
        /// Cut a 24-byte string into three 8-byte pieces.<br></br>
        /// 将 24 字节的字符串切割成三份，每份 8 字节。
        /// </summary>
        /// <param name="part1">Part1<br></br>第一部分</param>
        /// <param name="part2">Part2<br></br>第二部分</param>
        /// <param name="part3">Part3<br></br>第三部分</param>
        private void GetKey(out string part1, out string part2, out string part3)
        {
            if (Key.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 将输入字符串转换为字节数组
            byte[] bytes = Encoding.UTF8.GetBytes(Key);

            // 确保字节数组长度为 24
            if (bytes.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 切割字节数组为三份，每份 8 字节
            part1 = Encoding.UTF8.GetString(bytes, 0, 8);
            part2 = Encoding.UTF8.GetString(bytes, 8, 8);
            part3 = Encoding.UTF8.GetString(bytes, 16, 8);
        }

        /// <summary>
        /// Execute CBC string encryption mode.<br></br>
        /// 执行CBC字符串加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string CBCEncryptString(string text)
        {
            string originText = text;
            GetKey(out string part1, out string part2, out string part3);
            string encryptText1 = CBC.EncryptString(originText, part1, IV);
            string encryptText2 = CBC.EncryptString(encryptText1, part2, IV);
            string encryptText3 = CBC.EncryptString(encryptText2, part3, IV);
            return encryptText3;
        }

        /// <summary>
        /// Execute CBC string decryption mode.<br></br>
        /// 执行CBC字符串解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string CBCDecryptString(string text)
        {
            string encryptText = text;
            GetKey(out string part1, out string part2, out string part3);
            string decryptText1 = CBC.DecryptString(encryptText, part3, IV);
            string decryptText2 = CBC.DecryptString(decryptText1, part2, IV);
            string decryptText3 = CBC.DecryptString(decryptText2, part1, IV);
            return decryptText3;
        }

        /// <summary>
        /// Execute ECB string encryption mode.<br></br>
        /// 执行ECB字符串加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string ECBEncryptString(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            string originText = text;
            string encryptText1 = ECB.EncryptString(originText, part1);
            string encryptText2 = ECB.EncryptString(encryptText1, part2);
            string encryptText3 = ECB.EncryptString(encryptText2, part3);
            return encryptText3;
        }

        /// <summary>
        /// Execute ECB string decryption mode.<br></br>
        /// 执行ECB字符串解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string ECBDecryptString(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            string encryptText = text;
            string decryptText1 = ECB.DecryptString(encryptText, part3);
            string decryptText2 = ECB.DecryptString(decryptText1, part2);
            string decryptText3 = ECB.DecryptString(decryptText2, part1);
            return decryptText3;
        }
    }
}
