using System;
using System.Linq;

namespace QingYi.Crypto.DES.DesPlus.V1
{
    public static class Auxx
    {
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static byte[] XORBytes(byte[] a, byte[] b)
        {
            byte[] outer = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                outer[i] = (byte)(a[i] ^ b[i]);
            }

            return outer;
        }

        public static byte[] selectBits(byte[] inner, int pos, int len)
        {
            int numOfBytes = (len - 1) / 8 + 1;
            byte[] outer = new byte[numOfBytes];
            for (int i = 0; i < len; i++)
            {
                int val = getBitAt(inner, pos + i);
                setBitAt(outer, i, val);
            }

            return outer;
        }

        public static byte[] selectBits(byte[] inner, byte[] map)
        {
            int numOfBytes = (map.Length - 1) / 8 + 1;
            byte[] outer = new byte[numOfBytes];
            for (int i = 0; i < map.Length; i++)
            {
                int val = getBitAt(inner, map[i] - 1);
                setBitAt(outer, i, val);
            }

            return outer;
        }

        public static int getBitAt(byte[] data, int poz)
        {
            int posByte = poz / 8;
            int posBit = poz % 8;
            byte valByte = data[posByte];
            int valInt = valByte >> (7 - posBit) & 1;
            return valInt;
        }

        //ustawia lub kasuje bit na podanej pozycji w podanej tablicy bajtów
        public static void setBitAt(byte[] data, int pos, int val)
        {
            byte oldByte = data[pos / 8];
            oldByte = (byte)(((0xFF7F >> (pos % 8)) & oldByte) & 0x00FF);
            byte newByte = (byte)((val << (7 - (pos % 8))) | oldByte);
            data[pos / 8] = newByte;
        }

        public static byte[] rotateLeft(byte[] inner, int len, int step)
        {
            byte[] outer = new byte[(len - 1) / 8 + 1];
            for (int i = 0; i < len; i++)
            {
                int val = getBitAt(inner, (i + step) % len);
                setBitAt(outer, i, val);
            }

            return outer;
        }

        public static byte[] rotateRight(byte[] inner, int len, int step)
        {
            return rotateLeft(inner, len, 28 - step);
        }

        // public static String bytesToHex(byte bytes[])
        // {
        //     byte []rawData = bytes;
        //     StringBuilder hexText = new StringBuilder();
        //     String initialHex = null;
        //     int initHexLength = 0;
        //
        //     for (int i = 0; i < rawData.length; i++)
        //     {
        //         int positiveValue = rawData[i] & 0x000000FF;
        //         initialHex = Integer.toHexString(positiveValue);
        //         initHexLength = initialHex.length();
        //         while (initHexLength++ < 2)
        //         {
        //             hexText.append("0");
        //         }
        //         hexText.append(initialHex);
        //     }
        //     return hexText.toString();
        // }
    }
}
