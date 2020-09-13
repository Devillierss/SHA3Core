using System;
using System.Runtime.InteropServices;
using System.Text;
using NUnit.Framework;
using SHA3KeccakCore;
using SHA3KeccakCore.Enums;
using SHA3KeccakCore.Keccak;
using SHA3KeccakCore.SHA3;

namespace UnitTests
{
    public class KeccakTests
    {

        public byte[] _encodedBytes;

        string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";
        //string sentence = "TESTS";


        [Test(Description = "Keccak 128 Test")]
        public void Add_Sentence_Returns_Keccak_128_Hash_Bytes()
        {
            string expectedResult = "fc320e00951de2e1aefbeacd34121c82";

            var keccack = new Keccak(KeccakBitType.K128);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "Keccak 224 Test")]
        public void Add_Sentence_Returns_Keccak_224_Hash_Bytes()
        {
            string expectedResult = "981acc543e1c990f23726a9b63e63b528d7abd9be835d0c0680c148d";

            var keccack = new Keccak(KeccakBitType.K224);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "Keccak 256 Test")]
        public void Add_Sentence_Returns_Keccak_256_Hash_Bytes()
        {
            string expectedResult = "9c74507226afbf8a881e9c897e07c6ce938920a0a85a6c484125fac0cbd6dd48";

            var keccack = new Keccak(KeccakBitType.K256);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "Keccak 288 Test")]
        public void Add_Sentence_Returns_Keccak_288_Hash_Bytes()
        {
            string expectedResult = "b3dbf61b8c656b4d2c2c1737e8e24d0d9a6272a1e718df165f32c787bc8a9e925abed4e5";

            var keccack = new Keccak(KeccakBitType.K288);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "Keccak 384 Test")]
        public void Add_Sentence_Returns_Keccak_384_Hash_Bytes()
        {
            string expectedResult = "42075ff882c580f2dca6fe3513be1796baefd53143711b2a0e647fd868ec3f4c07ebd0afd75504dc684cc0132d6e41cc";

            var keccack = new Keccak(KeccakBitType.K384);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "Keccak 512 Test")]
        public void Add_Sentence_Returns_Keccak_512_Hash_Bytes()
        {
            string expectedResult = "c5d7346779f640937c4d8c538259a5c6edc871b01288fc0a80d4b10f32cf2df7c5a844268748acfd2c71219d636e522c755c84184a823698fa334b2844d5eaf3";

            var keccack = new Keccak(KeccakBitType.K512);

            var result = keccack.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }


        [Test(Description = "SHA3 224 Test")]
        public void Add_Sentence_Returns_SHA3_224_Hash_Bytes()
        {
            string expectedResult = "c854ecc2c0e97e265e4e0c263851e4ee75838c2e65f551af05c42f3a";

            var sha3 = new SHA3(SHA3BitType.S224);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }


        [Test(Description = "SHA3 256 Test")]
        public void Add_Sentence_Returns_SHA3_256_Hash_Bytes()
        {
            string expectedResult = "ce9c06f5ba188ac595a30c887a7539a74d5d682c2f5ce16d43ff163d98e5efb8";

            var sha3 = new SHA3(SHA3BitType.S256);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "SHA3 384 Test")]
        public void Add_Sentence_Returns_SHA3_384_Hash_Bytes()
        {
            string expectedResult = "90605b5796ab39964f46dcca1a808168a9e0d7db7a518c11ba2fa28323a9f5a4f265ddf999caa318162f23bfa57f0ad0";

            var sha3 = new SHA3(SHA3BitType.S384);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }


        [Test(Description = "SHA3 512 Test")]
        public void Add_Sentence_Returns_SHA3_512_Hash_Bytes()
        {
            string expectedResult = "8c4cf7ec3a273adc1b323ea5500c883576d1d24b9f656b36874b812c591a02dc93107547208853792fff06a94c9d8e83b9d9a7521a71a9e7c511119fe600c46f";

            var sha3 = new SHA3(SHA3BitType.S512);

            var result = sha3.Hash(sentence);

            Assert.AreEqual(expectedResult, result);
        }

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