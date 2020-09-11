using System;
using System.Collections.Generic;
using System.Text;
using SHA3KeccakCore.Enums;

namespace SHA3KeccakCore.SHA3
{
    public class SHA3 : Keccak1600
    {

        private readonly int _rateBytes;
        private readonly int _sha3Bits;

        public SHA3(SHA3BitType bitType)
        {
            _sha3Bits = (int)bitType;
            _rateBytes = Converters.ConvertBitLengthToRate(_sha3Bits);
        }

        public string Hash(string stringToHash)
        {

            var encodedBytes = Converters.ConvertStringToBytes(stringToHash);

            base.Initialize(new KeccakConfiguration() { RateBytes = _rateBytes, OutputLength = _sha3Bits / 8, HashType = HashType.Sha3 });
            base.Absorb(encodedBytes, 0, encodedBytes.Length);
            base.Partial(encodedBytes, 0, encodedBytes.Length);

            var byteResult = base.Squeeze();

            return Converters.ConvertBytesToStringHash(byteResult);
        }
    }
}
