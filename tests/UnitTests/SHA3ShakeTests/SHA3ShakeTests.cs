using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using SHA3KeccakCore.Enums;
using SHA3KeccakCore.SHA3;

namespace UnitTests.SHA3ShakeTests
{
    public class SHA3ShakeTests
    {
        string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";

        [Test(Description = "SHA3 Shake 128 Test")]
        public void Add_Sentence_Returns_SHA3_Shake_128_Hash_Bytes()
        {
            string expectedResult = "39977a3f5877f0077c5c26cf76cb047b";

            var sha3 = new SHA3Shake(ShakeBitType.S128);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "SHA3 Shake 256 Test")]
        public void Add_Sentence_Returns_SHA3_Shake_256_Hash_Bytes()
        {
            string expectedResult = "868f7cbb3d9bdb3c298f86ce11fec4b858c192c059a79e0247ab43c7b7de244c";

            var sha3 = new SHA3Shake(ShakeBitType.S256);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }
    }
}
