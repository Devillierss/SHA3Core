using System;
using System.Collections.Generic;
using System.Text;
using SHA3KeccakCore;
using SHA3KeccakCore.Enums;

namespace SHA3KeccakCore.Keccak
{
    public class Keccak : Keccak1600
    {
        private readonly int _rateBytes;
        private readonly int _keccakBits;

        public Keccak(KeccakBitType bitType)
        {
            _keccakBits = (int)bitType;
            _rateBytes = Converters.ConvertBitLengthToRate(_keccakBits);
        }

        public string Hash(string stringToHash)
        {

            var encodedBytes = Converters.ConvertStringToBytes(stringToHash);

            base.Initialize(new KeccakConfiguration() { RateBytes = _rateBytes, OutputLength = _keccakBits / 8, HashType = HashType.Keccak });
            base.Absorb(encodedBytes, 0, encodedBytes.Length);
            base.Partial(encodedBytes, 0, encodedBytes.Length);

            var byteResult = base.Squeeze();

            return Converters.ConvertBytesToStringHash(byteResult);
        }
    }
}
