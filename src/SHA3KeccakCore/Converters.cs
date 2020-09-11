using System;
using System.Collections.Generic;
using System.Text;

namespace SHA3KeccakCore
{
    public class Converters
    {
        internal static byte[] ConvertStringToBytes(string hash)
        {
            return Encoding.ASCII.GetBytes(hash);
        }

        internal static string ConvertBytesToStringHash(byte[] hashBytes)
        {
            return BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLower();
        }
    }
}
