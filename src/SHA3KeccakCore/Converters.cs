using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace SHA3KeccakCore
{
    public class Converters
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] ConvertStringToBytes(string hash)
        {
            return Encoding.ASCII.GetBytes(hash);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static string ConvertBytesToStringHash(byte[] hashBytes)
        {
            return BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLower();
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int ConvertBitLengthToRate(int bitLength)
        {
            return (1600 - (bitLength << 1)) / 8;
        }
    }
}
