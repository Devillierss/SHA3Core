using System;
using System.Runtime.InteropServices;
using System.Text;
using NUnit.Framework;
using SHA3KeccakCore;
using SHA3KeccakCore.Keccak;
using SHA3KeccakCore.SHA3;

namespace UnitTests
{
    public class KeccakTests
    {

        public byte[] _encodedBytes;

        string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";

        [SetUp]
        public void Setup()
        {
            
            //var sentence = "Test";
            //_encodedBytes = Encoding.ASCII.GetBytes(sentence);
        }

        [Test(Description = "Keccak 512 Test")]
        public void Add_Sentence_Returns_Hash_Bytes()
        {
            string expectedResult = "c5d7346779f640937c4d8c538259a5c6edc871b01288fc0a80d4b10f32cf2df7c5a844268748acfd2c71219d636e522c755c84184a823698fa334b2844d5eaf3";

            var keccack = new Keccak();

            var result = keccack.Hash(sentence);

            //keccack.Initialize();
            //keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
            //keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

            //var byteResult = keccack.Squeeze();
            //var result = BitConverter.ToString(byteResult).Replace("-", string.Empty).ToLower();

            Assert.AreEqual(expectedResult, result);
        }

        [Test(Description = "SHA3 512 Test")]
        public void Add_Sentence_Returns_SHA3_Hash_Bytes()
        {
            string expectedResult = "c5d7346779f640937c4d8c538259a5c6edc871b01288fc0a80d4b10f32cf2df7c5a844268748acfd2c71219d636e522c755c84184a823698fa334b2844d5eaf3";

            var sha3 = new SHA3();

            var result = sha3.Hash(sentence);

            //keccack.Initialize();
            //keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
            //keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

            //var byteResult = keccack.Squeeze();
            //var result = BitConverter.ToString(byteResult).Replace("-", string.Empty).ToLower();

            Assert.AreEqual(expectedResult, result);
        }

    }
}