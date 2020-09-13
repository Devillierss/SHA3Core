using System;
using System.Collections.Generic;
using System.Text;
using SHA3KeccakCore.Enums;

namespace SHA3KeccakCore.SHA3
{
    public class SHA3Shake : Keccak1600
    {
        public SHA3Shake(ShakeBitType bitType) :base((int)bitType)
        {
                
        }

        public string Hash(string stringToHash)
        {

            var encodedBytes = Converters.ConvertStringToBytes(stringToHash);

            base.Initialize((int)HashType.Shake);
            base.Absorb(encodedBytes, 0, encodedBytes.Length);
            base.Partial(encodedBytes, 0, encodedBytes.Length);

            var byteResult = base.Squeeze();

            return Converters.ConvertBytesToStringHash(byteResult);
        }
    }
}
