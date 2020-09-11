using System;
using System.Collections.Generic;
using System.Text;
using SHA3KeccakCore.Enums;

namespace SHA3KeccakCore
{
    public class KeccakConfiguration
    {
        public int RateBytes;
        public int OutputLength;
        public HashType HashType;
    }
}
