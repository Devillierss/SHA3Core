using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace SHA3KeccakCore.Enums
{
    public enum SHA3BitType
    {
        [Description("128")]
        S128 = 128,
        [Description("224")]
        S224 = 224,
        [Description("256")]
        S256 = 256,
        [Description("288")]
        S288 = 288,
        [Description("384")]
        S384 = 384,
        [Description("512")]
        S512 = 512,
    }
}
