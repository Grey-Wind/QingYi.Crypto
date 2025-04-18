using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace QingYi.Crypto.DES
{
    /// <summary>
    /// CBC mode.
    /// </summary>
    public class CBC
    {
        /// <summary>
        /// Encrypts the contents of a specified input file using DES encryption in CBC mode and writes the encrypted data to an output file.<br></br>
        /// 以CBC方式使用DES加密对指定输入文件的内容进行加密，并将加密后的数据写入输出文件。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="outputFile">The path to the output file where the encrypted data will be written.<br></br>将写入加密数据的输出文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist, and the output file will be created or overwritten.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。输入文件必须存在，输出文件将被创建或覆盖。
        /// </remarks>
        public static void EncryptFile(string inputFile, string outputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(fsOutput, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        int data;
                        while ((data = fsInput.ReadByte()) != -1)
                        {
                            csEncrypt.WriteByte((byte)data);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of a specified input file using DES decryption in CBC mode and writes the decrypted data to an output file.<br></br>
        /// 在CBC模式下使用DES解密对指定输入文件的内容进行解密，并将解密后的数据写入输出文件。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
        /// <param name="outputFile">The path to the output file where the decrypted data will be written.<br></br>将在其中写入解密数据的输出文件的路径。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist, and the output file will be created or overwritten.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。输入文件必须存在，输出文件将被创建或覆盖。
        /// </remarks>
        public static void DecryptFile(string inputFile, string outputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(fsInput, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        int data;
                        while ((data = csDecrypt.ReadByte()) != -1)
                        {
                            fsOutput.WriteByte((byte)data);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts the contents of a specified input file using DES encryption in CBC mode and returns the encrypted data as a byte array.<br></br>
        /// 以CBC模式使用DES加密对指定输入文件的内容进行加密，并以字节数组的形式返回加密后的数据。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the data to encrypt.<br></br>包含要加密的数据的输入文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A byte array containing the encrypted data.|包含加密数据的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保密钥和IV都被适当填充或根据需要截断为8字节。输入文件必须存在。
        /// </remarks>
        public static byte[] EncryptFileToBytes(string inputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (MemoryStream msOutput = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msOutput, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        int data;
                        while ((data = fsInput.ReadByte()) != -1)
                        {
                            csEncrypt.WriteByte((byte)data);
                        }
                    }

                    return msOutput.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of a specified input file using DES decryption in CBC mode and returns the decrypted data as a byte array.<br></br>
        /// 以CBC模式使用DES解密对指定输入文件的内容进行解密，并以字节数组的形式返回解密后的数据。
        /// </summary>
        /// <param name="inputFile">The path to the input file containing the encrypted data.<br></br>包含加密数据的输入文件的路径。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A byte array containing the decrypted data.|包含解密数据的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <exception cref="FileNotFoundException">Thrown when the input file does not exist.<br></br>当输入文件不存在时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed. The input file must exist.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保密钥和IV都被适当填充或根据需要截断为8字节。输入文件必须存在。
        /// </remarks>
        public static byte[] DecryptFileToBytes(string inputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (MemoryStream msOutput = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(fsInput, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        csDecrypt.CopyTo(msOutput);
                    }

                    return msOutput.ToArray();
                }
            }
        }

        /// <summary>
        /// Encrypts the contents of a byte array using DES encryption in CBC mode and writes the encrypted data to an output file.<br></br>
        /// 以CBC模式使用DES加密对字节数组的内容进行加密，并将加密后的数据写入输出文件。
        /// </summary>
        /// <param name="inputData">The byte array containing the data to encrypt.<br></br>包含要加密的数据的字节数组。</param>
        /// <param name="outputFile">The path to the output file where the encrypted data will be written.<br></br>将写入加密数据的输出文件的路径。</param>
        /// <param name="key">The encryption key as a string. It should be 8 characters long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8个字符长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 characters long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8个字符长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 characters).<br></br>当key或IV不是正确的长度(8个字符)时抛出。</exception>
        /// <exception cref="UnauthorizedAccessException">Thrown when the program lacks permissions to access the file system.<br></br>当程序缺乏访问文件系统的权限时抛出。</exception>
        public static void EncryptBytesToFile(byte[] inputData, string outputFile, string key, string iv)
        {
            if (key == null || key.Length != 8)
                throw new ArgumentException("The encryption key must be 8 characters long.", nameof(key));

            if (iv == null || iv.Length != 8)
                throw new ArgumentException("The IV must be 8 characters long.", nameof(iv));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(fsOutput, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(inputData, 0, inputData.Length);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the input byte array using DES decryption in CBC mode and writes the decrypted data to an output file.
        /// </summary>
        /// <param name="inputData">The encrypted byte array to decrypt.</param>
        /// <param name="outputFile">The path to the output file where the decrypted data will be written.</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each.
        /// </remarks>
        public static void DecryptBytesToFile(byte[] inputData, string outputFile, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msInput = new MemoryStream(inputData))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msInput, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        int data;
                        while ((data = csDecrypt.ReadByte()) != -1)
                        {
                            fsOutput.WriteByte((byte)data);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts the contents of a specified byte array using DES encryption in CBC mode and returns the encrypted data as a byte array.<br></br>
        /// 以CBC模式使用DES加密对指定字节数组的内容进行加密，并将加密后的数据作为字节数组返回。
        /// </summary>
        /// <param name="inputData">The byte array to encrypt.<br></br>要加密的字节数组。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>The encrypted byte array.|加密的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        public static byte[] EncryptBytes(byte[] inputData, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msOutput = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msOutput, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(inputData, 0, inputData.Length);
                        csEncrypt.FlushFinalBlock();
                    }

                    return msOutput.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts the contents of a specified input byte array using DES decryption in CBC mode and returns the decrypted data as a byte array.<br></br>
        /// 以CBC模式使用DES解密对指定输入字节数组的内容进行解密，并将解密后的数据作为字节数组返回。
        /// </summary>
        /// <param name="inputData">The encrypted byte array to decrypt.<br></br>要解密的加密字节数组。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>The decrypted byte array.|解密的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        public static byte[] DecryptBytes(byte[] inputData, string key, string iv)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msInput = new MemoryStream(inputData))
                using (MemoryStream msOutput = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msInput, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        csDecrypt.CopyTo(msOutput);
                    }

                    return msOutput.ToArray();
                }
            }
        }

        /// <summary>
        /// Encrypts a plain text string using DES encryption in CBC mode and returns the result as a Base64-encoded string.<br></br>
        /// 以CBC模式使用DES加密对纯文本字符串进行加密，并将结果作为base64编码的字符串返回。
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.<br></br>要加密的纯文本。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A Base64-encoded string representing the encrypted data.|表示加密数据的base64编码字符串。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).|当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static string EncryptString(string plainText, string key, string iv)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a Base64-encoded encrypted text string using DES decryption in CBC mode and returns the result as a plain text string.<br></br>
        /// 使用CBC模式下的DES解密base64编码的加密文本字符串，并将结果作为纯文本字符串返回。
        /// </summary>
        /// <param name="encryptedText">The Base64-encoded encrypted text to decrypt.<br></br>要解密的base64编码的加密文本。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>The decrypted plain text string.|解密后的纯文本字符串。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static string DecryptString(string encryptedText, string key, string iv)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts a plain text string using DES encryption in CBC mode and returns the result as a byte array.<br></br>
        /// 以CBC模式使用DES加密对纯文本字符串进行加密，并将结果作为字节数组返回。
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.<br></br>要加密的纯文本。</param>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A byte array representing the encrypted data.|表示加密数据的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES encryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES加密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static byte[] EncryptStringToBytes(string plainText, string key, string iv)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, desAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                        csEncrypt.FlushFinalBlock();
                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a Base64-encoded encrypted text string using DES decryption in CBC mode and returns the result as a byte array.<br></br>
        /// 使用CBC模式下的DES解密base64编码的加密文本字符串，并将结果作为字节数组返回。
        /// </summary>
        /// <param name="encryptedText">The Base64-encoded encrypted text to decrypt.<br></br>要解密的base64编码的加密文本。</param>
        /// <param name="key">The decryption key as a string. It should be 8 bytes long for DES.<br></br>作为字符串的解密密钥。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <returns>A byte array representing the decrypted plain text.|表示解密的纯文本的字节数组。</returns>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).<br></br>当key或IV不是正确的长度(8字节)时抛出。</exception>
        /// <remarks>
        /// DES decryption requires the key and IV to be exactly 8 bytes each. Ensure that both the key and IV are properly padded or truncated to 8 bytes as needed.<br></br>
        /// DES解密要求密钥和IV各为8字节。确保键和IV都被适当填充或根据需要截断为8字节。
        /// </remarks>
        public static byte[] DecryptStringToBytes(string encryptedText, string key, string iv)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (System.Security.Cryptography.DES desAlg = System.Security.Cryptography.DES.Create())
            {
                desAlg.Mode = CipherMode.CBC;
                desAlg.Key = keyBytes;
                desAlg.IV = ivBytes;

                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, desAlg.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream msPlainText = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msPlainText);
                            return msPlainText.ToArray();
                        }
                    }
                }
            }
        }

    }
}
