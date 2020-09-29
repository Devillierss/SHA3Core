using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Internal;
using Org.BouncyCastle.Crypto.Digests;
using SHA3Core;
using SHA3Core.Enums;
using SHA3Core.SHA3;

namespace UnitTests.SHA3Tests
{
    public class SHA3Tests
    {
        //string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";
        ////string sentence = "";

        //private string _1000000;// = new String(new char()., 1000000);
        ////private byte[] _holyshit = new byte[1073741824];
        ////private string _holyShit;


        //private static StringBuilder DuplicateString(string duplicate, int iterations)
        //{
        //    return new StringBuilder(duplicate.Length * iterations).AppendJoin(duplicate, new string[iterations +1]);
        //}


        //[SetUp]
        //public void Setup()
        //{
            //_1000000 = string.Concat(Enumerable.Repeat("a", 1000000));

            //var newstring = new StringBuilder();
            //var ok = DuplicateString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216);

            //_holyShit = string.Concat(Enumerable.Repeat("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216));


            //byte[] test = Converters.ConvertStringToBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");


            

            //int lastDestination = 0;


            //for (int i = 0; i < 16777216; i++)
            //{
            //    Array.Copy(test,0, holyshit, );
            //}

            //for (int i = 0; i < 16777216; i++)
            //{

            //    Array.Copy(test, 0, _holyshit, lastDestination, test.Length);
            //    lastDestination += test.Length;
            //}




            //Console.WriteLine(test);

            //_1000000 = DuplicateString("a", 1000000);
            //var test = DuplicateString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216);


            //var tosting = test.ToString();

            //Console.WriteLine("fook");
        //}

        
        //[Test]
        //public void A_1_000_000Test()
        //{
        //    string expectedResult = "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c";

        //    var sha3 = new SHA3(SHA3BitType.S224);

        //    var result = sha3.Hash(_1000000);


        //    var test = SetupTestSharedData.GetSha3TestVectors();




        //    var resultHuge = sha3.Hash(test[""]);

        //    Assert.AreEqual(expectedResult, result);
        //}


        //[Test(Description = "SHA3 224 Test")]
        //public void Add_Sentence_Returns_SHA3_224_Hash_Bytes()
        //{

        //    string expectedResult = "c854ecc2c0e97e265e4e0c263851e4ee75838c2e65f551af05c42f3a";

        //    var sha3 = new SHA3(SHA3BitType.S224);

        //    var result = sha3.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}


        //[Test(Description = "SHA3 256 Test")]
        //public void Add_Sentence_Returns_SHA3_256_Hash_Bytes()
        //{
        //    string expectedResult = "ce9c06f5ba188ac595a30c887a7539a74d5d682c2f5ce16d43ff163d98e5efb8";

        //    var sha3 = new SHA3(SHA3BitType.S256);

        //    var result = sha3.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "SHA3 384 Test")]
        //public void Add_Sentence_Returns_SHA3_384_Hash_Bytes()
        //{
        //    string expectedResult = "90605b5796ab39964f46dcca1a808168a9e0d7db7a518c11ba2fa28323a9f5a4f265ddf999caa318162f23bfa57f0ad0";

        //    var sha3 = new SHA3(SHA3BitType.S384);

        //    var result = sha3.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}


        //[Test(Description = "SHA3 512 Test")]
        //public void Add_Sentence_Returns_SHA3_512_Hash_Bytes()
        //{
        //    string expectedResult = "8c4cf7ec3a273adc1b323ea5500c883576d1d24b9f656b36874b812c591a02dc93107547208853792fff06a94c9d8e83b9d9a7521a71a9e7c511119fe600c46f";

        //    var sha3 = new SHA3(SHA3BitType.S512);

        //    var result = sha3.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        ////[Test, TestCaseSource(typeof(SetupTestSharedData)),

        //[Test, TestCaseSource(typeof(SetupTestSharedData), "GetSha224")]
        //public void TestDynamic224(TestDataValues testDataValues)
        //{
        //    var sha3 = new SHA3(SHA3BitType.S224);
            
        //    var result = testDataValues.InputMessage == null ? sha3.Hash(testDataValues.InputBytes) : sha3.Hash(testDataValues.InputMessage);

        //    Assert.AreEqual(testDataValues.ExpectedResult, result);


        //}

        [TestCaseSource(typeof(SetupTestSharedData), "GetSha224")]
        public string TestTestcase(TestDataValues testDataValues)
        {
            //TestCaseData display = new TestCaseData();
            //display.SetName(testDataValues.InputMessage);


            //var test = ((SHA3BitType) (testDataValues.BitLength));

            var sha3 = new SHA3((SHA3BitType)(testDataValues.BitLength));

            var result = testDataValues.InputMessage == null ? sha3.Hash(testDataValues.InputBytes) : sha3.Hash(testDataValues.InputMessage);

            return result;
            //Assert.AreEqual(testDataValues.ExpectedResult, result);

        }
    }
}
