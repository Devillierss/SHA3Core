using SHA3Core.Enums;

namespace SHA3Core.SHA3
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

        public string Hash(byte[] bytesToHash)
        {


            base.Initialize((int)HashType.Shake);
            base.Absorb(bytesToHash, 0, bytesToHash.Length);
            base.Partial(bytesToHash, 0, bytesToHash.Length);

            var byteResult = base.Squeeze();

            return Converters.ConvertBytesToStringHash(byteResult);
        }
    }
}
