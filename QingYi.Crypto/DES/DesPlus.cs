using System.Text;
using System;

namespace QingYi.Crypto.DES
{
    public class DesPlus
    {
        /// <summary>
        /// Specifies the block cipher mode to use for encryption.<br />
        /// 指定要用于加密的分组密码模式。
        /// </summary>
        public enum CipherMode
        {
            /// <summary>
            /// ECB
            /// </summary>
            ECB,
            /// <summary>
            /// CBC
            /// </summary>
            CBC
        }

        /// <summary>
        /// Specifies the type of padding to apply when the message data block is shorter than the full number of bytes needed for a cryptographic operation.<br />
        /// 指定当消息数据块短于加密操作所需的完整字节数时应用的填充类型。
        /// </summary>
        public enum PaddingMode
        {
            /// <summary>
            /// None
            /// </summary>
            None,

            /// <summary>
            /// PKCS5
            /// </summary>
            PKCS5,

            /// <summary>
            /// PKCS7
            /// </summary>
            PKCS7,

            /// <summary>
            /// Zeros
            /// </summary>
            Zeros
        }

        // 初始置换表 (IP)
        private static readonly int[] IPTable = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

        // 逆初始置换表 (IP^-1)
        private static readonly int[] FPTable = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

        // 密钥生成相关置换表
        private static readonly int[] PC1Table = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };

        private static readonly int[] PC2Table = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

        private static readonly int[] KeyShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        // Feistel函数相关表
        private static readonly int[] ETable = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

        private static readonly int[][,] SBoxes = {
    new int[,] { // S1
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    new int[,] { // S2
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    new int[,] { // S3
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    new int[,] { // S4
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    new int[,] { // S5
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    new int[,] { // S6
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    new int[,] { // S7
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    new int[,] { // S8
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

        private static readonly int[] PTable = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };

        private readonly byte[][] _subKeys = new byte[16][];

        // 核心加密方法
        public char[] Encrypt(char[] input, char[] keyChars, CipherMode mode, PaddingMode padding, char[] ivChars)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] key = ValidateKey(keyChars);
            byte[] iv = ValidateIV(ivChars, mode);

            // 处理填充
            byte[] paddedData = ApplyPadding(inputBytes, padding);

            // 生成子密钥
            ScheduleKeys(key);

            // 加密处理
            byte[] encrypted = mode == CipherMode.ECB ?
                EncryptECB(paddedData) :
                EncryptCBC(paddedData, iv);

            return Encoding.UTF8.GetChars(encrypted);
        }

        // 核心解密方法（结构类似，省略具体实现）

        private byte[] ValidateKey(char[] keyChars)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyChars);
            if (key.Length != 8) throw new ArgumentException("Key must be 8 characters");
            return key;
        }

        private byte[] ValidateIV(char[] ivChars, CipherMode mode)
        {
            if (mode == CipherMode.CBC && (ivChars == null || ivChars.Length != 8))
                throw new ArgumentException("IV must be 8 characters in CBC mode");
            return ivChars != null ? Encoding.UTF8.GetBytes(ivChars) : null;
        }

        // 填充处理
        private byte[] ApplyPadding(byte[] data, PaddingMode padding)
        {
            int blockSize = 8;
            int padBytes = blockSize - (data.Length % blockSize);

            switch (padding)
            {
                case PaddingMode.None:
                    if (data.Length % blockSize != 0)
                        throw new ArgumentException("Data length must be multiple of block size");
                    return data;

                case PaddingMode.PKCS5:
                case PaddingMode.PKCS7:
                    byte[] padded = new byte[data.Length + padBytes];
                    Array.Copy(data, padded, data.Length);
                    for (int i = data.Length; i < padded.Length; i++)
                        padded[i] = (byte)padBytes;
                    return padded;

                case PaddingMode.Zeros:
                    byte[] zeros = new byte[data.Length + padBytes];
                    Array.Copy(data, zeros, data.Length);
                    return zeros;

                default: throw new NotSupportedException();
            }
        }

        // 密钥调度
        private unsafe void ScheduleKeys(byte[] key)
        {
            fixed (byte* keyPtr = key)
            {
                byte[] pc1 = new byte[7];
                fixed (byte* pc1Ptr = pc1)
                {
                    Permute(keyPtr, pc1Ptr, PC1Table);
                }

                uint c = GetBits(pc1, 0, 28);
                uint d = GetBits(pc1, 28, 28);

                for (int i = 0; i < 16; i++)
                {
                    c = LeftShift28(c, KeyShifts[i]);
                    d = LeftShift28(d, KeyShifts[i]);

                    byte[] combined = CombineBits(c, d);
                    _subKeys[i] = new byte[6];

                    fixed (byte* combinedPtr = combined)
                    fixed (byte* subKeyPtr = _subKeys[i])
                    {
                        Permute(combinedPtr, subKeyPtr, PC2Table);
                    }
                }
            }
        }

        // ECB模式加密
        private unsafe byte[] EncryptECB(byte[] data)
        {
            byte[] output = new byte[data.Length];
            fixed (byte* inputPtr = data, outputPtr = output)
            {
                for (int i = 0; i < data.Length; i += 8)
                    EncryptBlock(inputPtr + i, outputPtr + i);
            }
            return output;
        }

        // CBC模式加密
        private unsafe byte[] EncryptCBC(byte[] data, byte[] iv)
        {
            byte[] output = new byte[data.Length];
            byte[] prev = new byte[8];
            Array.Copy(iv, prev, 8);

            fixed (byte* inputPtr = data, outputPtr = output, prevPtr = prev)
            {
                byte[] tempBlock = new byte[8];
                fixed (byte* tempBlockPtr = tempBlock)
                {
                    for (int i = 0; i < data.Length; i += 8)
                    {
                        // 异或输入块和前一个密文块
                        XorBlocks(inputPtr + i, prevPtr, tempBlockPtr, 8);

                        // 加密异或后的块
                        EncryptBlock(tempBlockPtr, outputPtr + i);

                        // 更新前一个密文块
                        for (int j = 0; j < 8; j++)
                            prevPtr[j] = outputPtr[i + j];
                    }
                }
            }
            return output;
        }

        // 核心加密块处理
        private unsafe void EncryptBlock(byte* input, byte* output)
        {
            byte[] block = new byte[8];
            fixed (byte* blockPtr = block)
            {
                Permute(input, blockPtr, IPTable);
            }

            uint left = GetBits(block, 0, 32);
            uint right = GetBits(block, 32, 32);

            for (int i = 0; i < 16; i++)
            {
                uint temp = right;
                right = left ^ Feistel(right, _subKeys[i]);
                left = temp;
            }

            byte[] final = CombineBits(right, left);
            fixed (byte* finalPtr = final)
            {
                Permute(finalPtr, output, FPTable);
            }
        }

        // Feistel函数实现
        private unsafe uint Feistel(uint right, byte[] subKey)
        {
            // 1. 扩展置换（32bit -> 48bit）
            byte[] expanded = new byte[6];
            fixed (byte* expandedPtr = expanded)
            {
                Permute((byte*)&right, expandedPtr, ETable);
            }

            // 2. 与子密钥异或
            fixed (byte* subKeyPtr = subKey)
            fixed (byte* expandedPtr = expanded)
            {
                for (int i = 0; i < 6; i++)
                    expandedPtr[i] ^= subKeyPtr[i];
            }

            // 3. S盒替换（48bit -> 32bit）
            uint result = 0;
            fixed (byte* expandedPtr = expanded)
            {
                for (int i = 0; i < 8; i++)
                {
                    // 获取6位输入
                    byte val = Get6Bits(expandedPtr, i * 6);

                    // 计算行和列
                    int row = ((val & 0x20) >> 4) | (val & 0x01); // 首位和末位
                    int col = (val & 0x1E) >> 1; // 中间4位

                    // 从对应S盒取值
                    int sVal = SBoxes[i][row, col];

                    // 组合结果
                    result = (result << 4) | (uint)(sVal & 0x0F);
                }
            }

            // 4. P置换
            byte[] pOutput = new byte[4];
            fixed (byte* pOutputPtr = pOutput)
            {
                // 将uint转换为byte[4]进行置换
                byte[] resultBytes = BitConverter.GetBytes(result);
                fixed (byte* resultPtr = resultBytes)
                {
                    Permute(resultPtr, pOutputPtr, PTable);
                }
            }

            // 从置换结果还原uint
            return GetBits(pOutput, 0, 32);
        }

        // 辅助方法：从字节数组获取指定位
        private static unsafe byte Get6Bits(byte* data, int startBit)
        {
            byte val = 0;
            for (int i = 0; i < 6; i++)
            {
                int bytePos = (startBit + i) / 8;
                int bitPos = 7 - (startBit + i) % 8;
                val <<= 1;
                val |= (byte)((data[bytePos] >> bitPos) & 0x01);
            }
            return val;
        }

        // 辅助方法：从字节数组获取指定位到uint
        private static unsafe uint GetBits(byte[] data, int startBit, int length)
        {
            uint result = 0;
            fixed (byte* dataPtr = data)
            {
                for (int i = 0; i < length; i++)
                {
                    int bytePos = (startBit + i) / 8;
                    int bitPos = 7 - (startBit + i) % 8;
                    result = (result << 1) | (uint)((dataPtr[bytePos] >> bitPos) & 0x01u);
                }
            }
            return result;
        }

        // 辅助方法：合并两个32位数到字节数组
        private static byte[] CombineBits(uint left, uint right)
        {
            byte[] output = new byte[8];
            unsafe
            {
                fixed (byte* outputPtr = output)
                {
                    // 处理左半部分
                    for (int i = 0; i < 32; i++)
                    {
                        int bitPos = 31 - i;
                        byte bit = (byte)((left >> bitPos) & 0x01);
                        int byteIndex = i / 8;
                        int outBitPos = 7 - (i % 8);
                        outputPtr[byteIndex] |= (byte)(bit << outBitPos);
                    }

                    // 处理右半部分
                    for (int i = 0; i < 32; i++)
                    {
                        int bitPos = 31 - i;
                        byte bit = (byte)((right >> bitPos) & 0x01);
                        int byteIndex = 4 + i / 8;
                        int outBitPos = 7 - (i % 8);
                        outputPtr[byteIndex] |= (byte)(bit << outBitPos);
                    }
                }
            }
            return output;
        }

        // 辅助方法（位操作、置换等）
        private unsafe void Permute(byte* input, byte* output, int[] table)
        {
            int outputLength = (table.Length + 7) / 8; // 计算输出字节数
            for (int i = 0; i < outputLength; i++)
                output[i] = 0; // 清空输出缓冲区

            for (int i = 0; i < table.Length; i++)
            {
                int srcPos = table[i] - 1; // 调整为0-based索引
                int srcByte = srcPos / 8;
                int srcBit = 7 - (srcPos % 8);
                byte bit = (byte)((input[srcByte] >> srcBit) & 0x01);

                int destByte = i / 8;
                int destBit = 7 - (i % 8);
                output[destByte] |= (byte)(bit << destBit);
            }
        }

        // 辅助方法：28位循环左移
        private static uint LeftShift28(uint value, int shift)
        {
            return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFFu; // 保持28位
        }

        // 辅助方法：异或块操作
        private static unsafe void XorBlocks(byte* a, byte* b, byte* result, int length)
        {
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }
    }
}
