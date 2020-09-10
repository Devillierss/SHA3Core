using System;
using System.Collections.Generic;
using System.Text;

namespace SHA3KeccakCore
{
    public enum HashType
    {
        Keccak = 0x01,
        Sha3 = 0x06,
        Shake = 0x1f,
        CShake = 0x04
    }
}
