using System;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Digests;
using SHA3Core;
using SHA3Core.Enums;
using SHA3Core.Keccak;

namespace UnitTests.KeccakTests
{
    public class KeccakTests
    {
        string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";


        //[Test(Description = "Keccak 128 Test")]
        //public void Add_Sentence_Returns_Keccak_128_Hash_Bytes()
        //{
        //    string expectedResult = "fc320e00951de2e1aefbeacd34121c82";

        //    var keccack = new Keccak(KeccakBitType.K128);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "Keccak 224 Test")]
        //public void Add_Sentence_Returns_Keccak_224_Hash_Bytes()
        //{
        //    string expectedResult = "981acc543e1c990f23726a9b63e63b528d7abd9be835d0c0680c148d";

        //    var keccack = new Keccak(KeccakBitType.K224);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "Keccak 256 Test")]
        //public void Add_Sentence_Returns_Keccak_256_Hash_Bytes()
        //{
        //    string expectedResult = "9c74507226afbf8a881e9c897e07c6ce938920a0a85a6c484125fac0cbd6dd48";

        //    var keccack = new Keccak(KeccakBitType.K256);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "Keccak 288 Test")]
        //public void Add_Sentence_Returns_Keccak_288_Hash_Bytes()
        //{
        //    string expectedResult = "b3dbf61b8c656b4d2c2c1737e8e24d0d9a6272a1e718df165f32c787bc8a9e925abed4e5";

        //    var keccack = new Keccak(KeccakBitType.K288);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "Keccak 384 Test")]
        //public void Add_Sentence_Returns_Keccak_384_Hash_Bytes()
        //{
        //    string expectedResult = "42075ff882c580f2dca6fe3513be1796baefd53143711b2a0e647fd868ec3f4c07ebd0afd75504dc684cc0132d6e41cc";

        //    var keccack = new Keccak(KeccakBitType.K384);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}

        //[Test(Description = "Keccak 512 Test")]
        //public void Add_Sentence_Returns_Keccak_512_Hash_Bytes()
        //{
        //    string expectedResult = "c5d7346779f640937c4d8c538259a5c6edc871b01288fc0a80d4b10f32cf2df7c5a844268748acfd2c71219d636e522c755c84184a823698fa334b2844d5eaf3";

        //    var keccack = new Keccak(KeccakBitType.K512);

        //    var result = keccack.Hash(sentence);

        //    Assert.AreEqual(expectedResult, result);
        //}


        //private string hex2binary(string hexvalue) { string binaryval = ""; binaryval = Convert.ToString(Convert.ToInt64(hexvalue, 16), 2); return binaryval; }


        //[Test]
        //[Repeat(10)]
        //public void Test()
        //{
        //    //var random = "1F42ADD25C0A80A4C82AAE3A0E302ABF9261DCA7E7884FD869D96ED4CE88AAAA25304D2D79E1FA5CC1FA2C95899229BC87431AD06DA524F2140E70BD0536E9685EE7808F598D8A9FE15D40A72AEFF431239292C5F64BDB7F620E5D160B329DEB58CF6D5C0665A3DED61AE4ADBCA94DC2B7B02CDF3992FDF79B3D93E546D5823C3A630923064ED24C3D974C4602A49DF75E49CF7BD51EDC7382214CBA850C4D3D11B40A70B1D926E3755EC79693620C242AB0F23EA206BA337A7EDC5421D63126CB6C7094F6BC1CF9943796BE2A0D9EB74FC726AA0C0D3B3D39039DEAD39A7169F8C3E2365DD349E358BF08C717D2E436D65172A76ED5E1F1E694A75C19280B15";

        //    //var og = hex2binary(random);

        //    //var random = "1F42ADD25C0A80A4C82AAE3A0E302ABF9261DCA7E7884FD869D96ED4CE88AAAA25304D2D79E1FA5CC1FA2C95899229BC87431AD06DA524F2140E70BD0536E9685EE7808F598D8A9FE15D40A72AEFF431239292C5F64BDB7F620E5D160B329DEB58CF6D5C0665A3DED61AE4ADBCA94DC2B7B02CDF3992FDF79B3D93E546D5823C3A630923064ED24C3D974C4602A49DF75E49CF7BD51EDC7382214CBA850C4D3D11B40A70B1D926E3755EC79693620C242AB0F23EA206BA337A7EDC5421D63126CB6C7094F6BC1CF9943796BE2A0D9EB74FC726AA0C0D3B3D39039DEAD39A7169F8C3E2365DD349E358BF08C717D2E436D65172A76ED5E1F1E694A75C19280B15";
        //    //var random = new Bogus.Randomizer();
        //    var lorem = new Bogus.DataSets.Lorem("en");

        //    var randomint = new Random().Next(1000);

        //    var go = lorem.Paragraph(randomint);

        //    var keccack = new Keccak(KeccakBitType.K512);

        //    var result = keccack.Hash(go);
        //    var expectedResult = BouncingCastleHash(go);

        //    Assert.AreEqual(expectedResult, result);

        //    Console.WriteLine(go);

        //}


        //private string BouncingCastleHash(string testString)
        //{
        //    var encodedBytes =Converters.ConvertStringToBytes(testString);



        //    KeccakDigest test = new KeccakDigest(512);

        //    var hashValue = new byte[test.GetDigestSize()];

        //    test.BlockUpdate(encodedBytes, 0, encodedBytes.Length);

        //    test.DoFinal(hashValue, 0);

        //    return BitConverter.ToString(hashValue).Replace("-", string.Empty).ToLower();
        //}


    }
}