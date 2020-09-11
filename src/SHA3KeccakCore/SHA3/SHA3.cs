using System;
using System.Collections.Generic;
using System.Text;

namespace SHA3KeccakCore.SHA3
{
    public class SHA3 : Keccak1600
    {
        public SHA3():base(new KeccakConfiguration(){ RateBytes = 72, OutputLength = 64, HashType = HashType.Sha3 })
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
