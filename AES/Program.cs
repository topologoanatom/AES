using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics;

public class AES
{
    static List<BitArray> subBytesMatrix = new List<BitArray>() { new BitArray(new byte[] { 0b11110001 }), new BitArray(new byte[] { 0b11100011 }), new BitArray(new byte[] { 0b11000111}),
                                                                  new BitArray(new byte[] { 0b10001111 }), new BitArray(new byte[] { 0b00011111 }), new BitArray(new byte[] { 0b00111110}),
                                                                  new BitArray(new byte[] { 0b01111100 }), new BitArray(new byte[] { 0b11111000 })
    };
   
    static byte[] AntiLogArray = new byte[255] { 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1 };

    static byte[] LogArray = new byte[256] { 0, 255, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7 };

    static byte[] SArray = GenerateSArray();
    static byte[] rcI = new byte[10] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    static void Main()
    {
        var watch = new Stopwatch();
        var key = GenerateCTRKey();
        byte[] plaintext = RandomNumberGenerator.GetBytes(1 << 7);
        byte[] copy = new byte[plaintext.Length];
        plaintext.CopyTo(copy, 0);
        watch.Start();
        EncryptCTR(copy, key);
        EncryptCTR(copy, key);
        watch.Stop();
        Console.WriteLine(watch.ElapsedMilliseconds);

        for (int i = 0; i < 1 << 7; i++)
        {
            Console.WriteLine($"{i} {plaintext[i] == copy[i]}");
        }
    }

    public static void EncryptCTR(byte[] plaintext, byte[][][] key)
    {
        int mainPartIndex = plaintext.Length >> 4;

        Parallel.For<Byte4x4>(0, mainPartIndex, () => new Byte4x4(), (index, _, local) =>
        {
            index = index << 4;

            Array.Copy(plaintext, index, local.state[0], 0, 4);
            Array.Copy(plaintext, index + 4, local.state[1], 0, 4);
            Array.Copy(plaintext, index + 8, local.state[2], 0, 4);
            Array.Copy(plaintext, index + 12, local.state[3], 0, 4);

            byte[] counter = BitConverter.GetBytes(index);
            Array.Copy(key[11][0], 0, local.key[0], 0, 4);
            Array.Copy(key[11][1], 0, local.key[1], 0, 4);
            Array.Copy(key[11][2], 0, local.key[2], 0, 4);
            Array.Copy(counter, 0, local.key[3], 0, 4);

            EncryptVoid(local.key, key);
            local.state = StateXOR(local.state, local.key);

            Array.Copy(local.state[0], 0, plaintext, index, 4);
            Array.Copy(local.state[1], 0, plaintext, index + 4, 4);
            Array.Copy(local.state[2], 0, plaintext, index + 8, 4);
            Array.Copy(local.state[3], 0, plaintext, index + 12, 4);

            return local;
        }, (_) => { });

        if (plaintext.Length - (mainPartIndex << 4) == 0) 
        {
            return;
        }
        byte[][] block = new byte[4][];
        byte[][] counterKey = new byte[4][] { new byte[4], new byte[4], new byte[4], new byte[4] };
        byte[] counter;
        byte[] remainder = new byte[16];
        int j = mainPartIndex << 4;
        for (int i = 0; i < 16; i++)
        {
            if (j + i < plaintext.Length)
            {
                remainder[i] = plaintext[j + i];
            }
            else
            {
                remainder[i] = 0x00;
            }
        }
        block[0] = new byte[4] { remainder[0], remainder[1], remainder[2], remainder[3] };
        block[1] = new byte[4] { remainder[4], remainder[5], remainder[6], remainder[7] };
        block[2] = new byte[4] { remainder[8], remainder[9], remainder[10], remainder[11] };
        block[3] = new byte[4] { remainder[12], remainder[13], remainder[14], remainder[15] };
        counter = BitConverter.GetBytes(mainPartIndex);
        Array.Copy(key[11][0], 0, counterKey[0], 0, 4);
        Array.Copy(key[11][1], 0, counterKey[1], 0, 4);
        Array.Copy(key[11][2], 0, counterKey[2], 0, 4);
        Array.Copy(counter, 0, counterKey[3], 0, 4);
        counterKey[3] = counter;
        EncryptVoid(counterKey, key);
        block = StateXOR(block, counterKey);
        Array.Copy(block[0], 0, remainder, 0, 4);
        Array.Copy(block[1], 0, remainder, 4, 4);
        Array.Copy(block[2], 0, remainder, 8, 4);
        Array.Copy(block[3], 0, remainder, 12, 4);
        for (int i = 0; i < plaintext.Length - j; i++) 
        {
            plaintext[j + i] = remainder[i];
        }
    }

    class Byte4x4
    {
        public byte[][] state = new byte[4][] { new byte[4], new byte[4], new byte[4], new byte[4] };
        public byte[][] key = new byte[4][] { new byte[4], new byte[4], new byte[4], new byte[4] };
    }
    public static byte[][][] GenerateCTRKey()
    {
        byte[][][] initialKey = GenerateKey(128, 11, 1);
        initialKey[initialKey.Length - 1] = new byte[][] { new byte[] { 0x01, 0xcf, 0xed, 0x6d }, new byte[] { 0x54, 0x3a, 0xce, 0x11 }, 
                                                           new byte[] { 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00, 0x00, 0x00 } };
        return initialKey;
    }

    static void EncryptVoid(byte[][] plaintext, byte[][][] key)
    {
        AddRoundKey(plaintext, key[0]);
        for (int i = 1; i < 10; i++)
        {
            stateSubBytes(plaintext);
            ShiftRows(plaintext);
            MixColumns(plaintext);
            AddRoundKey(plaintext, key[i]);
        }
        stateSubBytes(plaintext);
        ShiftRows(plaintext);
        AddRoundKey(plaintext, key[10]);
    }
    public static byte[][][] GenerateKey(int keySize, int rounds, int CTR)
    {
        byte[][][] result = new byte[rounds + CTR][][];
        int n = keySize >> 5;
        List<byte[]> initialKey = RandomNumberGenerator.GetBytes(keySize >> 3).Chunk(4).ToList();
        List<byte[]> expandedKey = new List<byte[]>();
        for (int i = 0; i < (rounds << 2); i++)
        {
            if (i < n)
            {
                expandedKey.Add(initialKey[i]);
                continue;
            }
            if (i >= n && i % n == 0)
            {
                byte[] next = RotWord(expandedKey[i - 1]);
                next = SubWord(next);
                byte[] rci = new byte[4] { rcI[(i / n) - 1], 0x00, 0x00, 0x00 };
                for (int j = 0; j < 4; j++)
                {
                    next[j] = (byte)((expandedKey[i - n][j] ^ next[j]) ^ rci[j]);
                }
                expandedKey.Add(next);
                continue;
            }
            else
            {
                byte[] next = new byte[4];
                expandedKey[i - 1].CopyTo(next, 0);
                for (int j = 0; j < 4; j++)
                {
                    next[j] = (byte)(next[j] ^ expandedKey[i - n][j]);
                }
                expandedKey.Add(next);
            }
        }
        byte[][] state = new byte[4][];
        int k = 1;
        foreach (var x in expandedKey)
        {
            state[(k - 1) % 4] = x;
            k++;
            if ((k - 1) % 4 == 0)
            {
                byte[][] copy = new byte[4][];
                state.CopyTo(copy, 0);
                result[(k / 4) - 1] = copy;
                Array.Clear(state);
            }
        }
        return result;
    }
    static byte[] RotWord(byte[] word)
    {
        return new byte[] { word[1], word[2], word[3], word[0] };
    }
    static byte[] SubWord(byte[] word)
    {
        for (int i = 0; i < word.Length; i++)
        {
            word[i] = SArray[word[i]];
        }
        return word;
    }
    static void AddRoundKey(byte[][] state, byte[][] key)
    {
        for (int j = 0; j < 4; j++)
        {
            for (int i = 0; i < 4; i++)
            {
                state[i][j] = (byte)(state[i][j] ^ key[i][j]);
            }
        }
    }

    static void MixColumns(byte[][] state)
    {
        for (int j = 0; j < 4; j++)
        {
            state[0][j] = (byte)(TableMultiply(0x02, state[0][j]) ^ TableMultiply(0x03, state[1][j]) ^ state[2][j] ^ state[3][j]);
            state[1][j] = (byte)(state[0][j] ^ TableMultiply(0x02, state[1][j]) ^ TableMultiply(0x03, state[2][j]) ^ state[3][j]);
            state[2][j] = (byte)(state[0][j] ^ state[1][j] ^ TableMultiply(0x02, state[2][j]) ^ TableMultiply(0x03, state[3][j]));
            state[3][j] = (byte)(TableMultiply(0x03, state[0][j]) ^ state[1][j] ^ state[2][j] ^ TableMultiply(0x02, state[3][j]));
        }
    }
    static void ShiftRows(byte[][] state)
    {
        state[1] = new byte[] { state[1][1], state[1][2], state[1][3], state[1][0], };
        state[2] = new byte[] { state[2][2], state[2][3], state[2][0], state[2][1], };
        state[3] = new byte[] { state[3][3], state[3][0], state[3][1], state[3][2], };
    }
    static void stateSubBytes(byte[][] state)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i][j] = SArray[state[i][j]];
            }
        }
    }
    static byte[] GenerateSArray()
    {
        byte[] result = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            result[i] = SubBytes((byte)(i));
        }
        return result;
    }
    static byte SubBytes(byte a)
    {
        byte inverse = GF256.Inverse(a);
        byte c = 0b01100011;
        BitArray bits = MatrixVectorProduct(subBytesMatrix, new BitArray(new byte[1] { inverse }));
        byte[] ba = new byte[1];
        bits.CopyTo(ba, 0);
        return (byte)(ba[0] ^ c);
    }
    static BitArray MatrixVectorProduct(List<BitArray> matrix, BitArray a)
    {
        BitArray result = new BitArray(8);
        for (int i = 0; i < matrix.Count; i++)
        {
            result[i] = ScalarProduct(matrix[i], a);
        }
        return result;
    }
    static bool ScalarProduct(BitArray a, BitArray b)
    {
        bool result = false;
        for (int i = 0; i < a.Count; i++)
        {
            result ^= a[i] & b[i];
        }
        return result;
    }
    public static byte TableMultiply(byte a, byte b)
    {
        int logA = LogArray[a];
        int logB = LogArray[b];
        int sum = logA + logB;
        sum = ((sum - 256) >> 31) + sum & 0xFF;
        return a == 0 || b == 0 ? (byte)0x00 : AntiLogArray[sum];
    }
    static byte[][] StateXOR(byte[][] a, byte[][] b)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                a[i][j] = (byte)(a[i][j] ^ b[i][j]);
            }
        }
        return a;
    }
}
class GF256
{
    static List<byte> modTable = new List<byte>(){ 0b00011011, 0b00110110, 0b01101100, 0b11011000, 0b10101011, 0b01001101, 0b10011010, 0b00101111 };
    public static byte Inverse(byte a)
    {
        if (a == 0) 
        {
            return 0;
        }
        return BinaryRaise(a, 254);
    }
    static byte xtime(byte a)
    {
        bool b = ((a >> 7) & 1) == 1;
        byte aOld = a;
        a = (byte)(a << 1);
        if(b)
        {
            a = (byte)(a ^ 0b00011011);
        }
        return (byte)(a ^ aOld);
    }
    public static byte BinaryRaise(byte a, int b)
    {
        string binary = Convert.ToString(b, 2);
        byte d = a;
        byte result = 0b00000001;
        for (int i = 0; i < binary.Length; i++)
        {
            if (binary[binary.Length - i - 1] == '1')
            {
                result = Multiply(result, d);
            }
            d = Multiply(d, d);
        }
        return result;
    }
    public static byte Multiply(byte a, byte b) 
    {
        List<int> nonZero1 = new List<int>();
        List<int> nonZero2 = new List<int>();
        for (int i = 0; i < 8; i++) 
        {
            if( ((a >> i) & 1) == 1) 
            {
                nonZero1.Add(i);
            }
            if (((b >> i) & 1) == 1)
            {
                nonZero2.Add(i);
            }
        }
        bool[] full = new bool[16];
        for (int i = 0; i < nonZero1.Count; i++) 
        {
            for (int j = 0; j < nonZero2.Count; j++)
            {
                full[nonZero1[i] + nonZero2[j]] ^= true;
            }
        }
        int t = 0;
        for (int i = 0; i < 8; i++) 
        {
            if (full[i]) 
            {
                t += (1 << i);
            }
        }
        byte result = (byte)t;
        for (int i = 8; i < 16; i++) 
        {
            if (full[i])
            {
                result = XOR(result, modTable[i - 8]);
            }
        }
        return result;
    }
    static byte XOR(byte a, byte b) 
    {
        return (byte)(a ^ b);
    }
}