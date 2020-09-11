using System;
using System.Collections.Generic;
using System.Text;
using SHA3KeccakCore;

namespace SHA3KeccakCore.Keccak
{
    public class Keccak : Keccak1600
    {

        public Keccak() :base(new KeccakConfiguration(){RateBytes = 72, OutputLength = 64, HashType = HashType.Keccak})
        {
        }

        public string Hash(string stringToHash)
        {

            var encodedBytes = Converters.ConvertStringToBytes(stringToHash);

            base.Initialize();
            base.Absorb(encodedBytes, 0, encodedBytes.Length);
            base.Partial(encodedBytes, 0, encodedBytes.Length);

            var byteResult = base.Squeeze();

            return Converters.ConvertBytesToStringHash(byteResult);

            //keccack.Initialize();
            //keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
            //keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

            //var byteResult = keccack.Squeeze();
            //var result = BitConverter.ToString(byteResult).Replace("-", string.Empty);
        }
    }
}
