using QingYi.Crypto.DES;
using System;
using System.Text;

namespace TripleDES
{
    /// <summary>
    /// 3DES file crypto. Based on the DES module of this library.<br></br>
    /// 3DES文件加密。基于本库的DES模块。
    /// </summary>
    public class TripleDesFileCrypto
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
        public TripleDesFileCrypto(string key, string iv)
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
        /// Execute CBC file encryption mode.<br></br>
        /// 执行CBC文件加密模式。
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="outputPath"></param>
        public void CBCEncryptFile(string filePath, string outputPath)
        {
            GetKey(out string part1, out string part2, out string part3);
            byte[] encrypt1 = CBC.EncryptFileToBytes(filePath, part1, IV);
            byte[] encrypt2 = CBC.EncryptBytes(encrypt1, part2, IV);
            CBC.EncryptBytesToFile(encrypt2, outputPath, part3, IV);
        }

        /// <summary>
        /// Execute CBC file decryption mode.<br></br>
        /// 执行CBC文件解密模式。
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="outputPath"></param>
        public void CBCDecryptFile(string filePath, string outputPath)
        {
            GetKey(out string part1, out string part2, out string part3);
            byte[] decrypt1 = CBC.DecryptFileToBytes(filePath, part3, IV);
            byte[] decrypt2 = CBC.DecryptBytes(decrypt1, part2, IV);
            CBC.DecryptBytesToFile(decrypt2, outputPath, part1, IV);
        }

        /// <summary>
        /// Execute ECB file encryption mode.<br></br>
        /// 执行ECB文件加密模式。
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="outputPath"></param>
        public void ECBEncryptFile(string filePath, string outputPath)
        {
            GetKey(out string part1, out string part2, out string part3);
            byte[] encrypt1 = ECB.EncryptFileToBytes(filePath, part1);
            byte[] encrypt2 = ECB.EncryptBytes(encrypt1, part2);
            ECB.EncryptBytesToFile(encrypt2, outputPath, part3);
        }

        /// <summary>
        /// Execute ECB file decryption mode.<br></br>
        /// 执行ECB文件解密模式。
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="outputPath"></param>
        public void ECBDecryptFile(string filePath, string outputPath)
        {
            GetKey(out string part1, out string part2, out string part3);
            byte[] decrypt1 = ECB.DecryptFileToBytes(filePath, part3);
            byte[] decrypt2 = ECB.DecryptBytes(decrypt1, part2);
            ECB.DecryptBytesToFile(decrypt2, outputPath, part1);
        }
    }
}
