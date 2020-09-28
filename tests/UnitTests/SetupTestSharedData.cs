using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math.EC.Rfc8032;
using SHA3Core;

namespace UnitTests
{
    public class SetupTestSharedData
    {



        private static readonly SetupTestSharedData SetupSingleTestSharedData = new SetupTestSharedData();
        private readonly byte[] GigaByte = new byte[1073741824];
        private string OneMillionA;
        private readonly List<TestDataValues> Sha3TestDataValues = new List<TestDataValues>();

        



        private SetupTestSharedData()
        {

            LoadGigaByteData();
            LoadOneMillionA();
            SetupSha3Cases();
        }

        private void LoadOneMillionA()
        {
            OneMillionA = string.Concat(Enumerable.Repeat("a", 1000000));
        }

        private void LoadGigaByteData()
        {

            byte[] test = Converters.ConvertStringToBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");

            int lastDestination = 0;
            for (int i = 0; i < 16777216; i++)
            {
                Array.Copy(test, 0, GigaByte, lastDestination, test.Length);
                lastDestination += test.Length;
            }

        }

        public static Dictionary<string, byte[]> GetSha3TestVectors()
        {

            var largeData = new Dictionary<string, byte[]>();
            largeData.Add("", SetupSingleTestSharedData.GigaByte);

            return largeData;
        }

        private void SetupSha3Cases()
        {


            List<TestCaseData> test = new List<TestCaseData>();
            test.Add(new TestCaseData(new TestDataValues()
            {
                InputMessage = "abc", BitLength = 224,
                ExpectedResult = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
            }).SetName("TestCaseONe"));

            
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abc",BitLength = 224,ExpectedResult = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "",BitLength = 224,ExpectedResult = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BitLength = 224,ExpectedResult = "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",BitLength = 224,ExpectedResult = "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = OneMillionA,BitLength = 224,ExpectedResult = "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputBytes = GigaByte,BitLength = 224,ExpectedResult = "c6d66e77ae289566afb2ce39277752d6da2a3c46010f1e0a0970ff60"});


            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abc",BitLength = 256,ExpectedResult = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "",BitLength = 256,ExpectedResult = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BitLength = 256,ExpectedResult = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",BitLength = 256,ExpectedResult = "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = OneMillionA,BitLength = 256,ExpectedResult = "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputBytes = GigaByte,BitLength = 256,ExpectedResult = "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b"});

            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abc",BitLength = 384,ExpectedResult = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "",BitLength = 384,ExpectedResult = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BitLength = 384,ExpectedResult = "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",BitLength = 384,ExpectedResult = "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = OneMillionA,BitLength = 384,ExpectedResult = "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputBytes = GigaByte,BitLength = 384,ExpectedResult = "a04296f4fcaae14871bb5ad33e28dcf69238b04204d9941b8782e816d014bcb7540e4af54f30d578f1a1ca2930847a12"});

            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abc",BitLength = 512,ExpectedResult = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "",BitLength = 512,ExpectedResult = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",BitLength = 512,ExpectedResult = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",BitLength = 512,ExpectedResult = "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputMessage = OneMillionA,BitLength = 512,ExpectedResult = "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"});
            Sha3TestDataValues.Add(new TestDataValues(){ InputBytes = GigaByte,BitLength = 512,ExpectedResult = "235ffd53504ef836a1342b488f483b396eabbfe642cf78ee0d31feec788b23d0d18d5c339550dd5958a500d4b95363da1b5fa18affc1bab2292dc63b7d85097c"});

        }

        public static IEnumerable<TestDataValues> GetSha224()
        {

            foreach (var sha3TestDataValue in SetupSingleTestSharedData.Sha3TestDataValues.Where(x => x.BitLength == 224))
            {
                yield return sha3TestDataValue;
            }


        }

    }
}
