using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Digests;
using SHA3KeccakCore.Enums;
using SHA3KeccakCore.SHA3;

namespace UnitTests.SHA3Tests
{
    public class SHA3Tests
    {
        string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";
        //string sentence = "";


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

        [Test]
        public void test()
        {

            byte[] bytes = new byte[4];
            bytes[0] = 83;
            bytes[1] = 88;
            bytes[2] = 123;
            bytes[3] = 25;


            var sha3 = new SHA3(SHA3BitType.S224);

            var result = sha3.Hash(bytes);

            Sha3Digest test = new Sha3Digest(224);

            var hashValue = new byte[test.GetDigestSize()];

            test.BlockUpdate(bytes, 0, bytes.Length);

            test.DoFinal(hashValue, 0);

            var bounciongResult = BitConverter.ToString(hashValue).Replace("-", string.Empty).ToLower();


            Console.WriteLine(test);
        }
    }
}
