using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.EC.Rfc8032;
using SHA3Core;

namespace UnitTests
{
    //[Parallelizable(ParallelScope.Children)]
    public class SetupTestSharedData
    {
        private static readonly SetupTestSharedData SetupSingleTestSharedData = new SetupTestSharedData();
        private readonly byte[] GigaByte = new byte[1073741824];
        private string OneMillionA;
        private readonly List<TestCaseData> Sha3TestDataValues = new List<TestCaseData>();
        private readonly List<TestCaseData> KeccakTestDataValues = new List<TestCaseData>();


        private SetupTestSharedData()
        {

            LoadGigaByteData();
            LoadOneMillionA();
            SetupSha3Cases();
            SetupKeccakTestCases();
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

        private void SetupKeccakTestCases()
        {

            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 128 }).Returns("bcf56ac882ad981cd0fa74f0f397572c").SetName("Keccak-128-0bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 128 }).Returns("ed992674a628509bb2dce176b7c03672").SetName("Keccak-128-24bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 128 }).Returns("b35ea9fbde7c7766d55222e3a6e22c13").SetName("Keccak-128-448bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 128 }).Returns("5a1e08d8b4e612154567b2d316b985bc").SetName("Keccak-128-896bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 128 }).Returns("79e7c4ad148f96007e7c198e2a0a7897").SetName("Keccak-128-AOneMillion"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 128 }).Returns("10e515946dba3b8c17ec5fd36af43b6c").SetName("Keccak-128-GigaByte of Data"));



            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 224 }).Returns("f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd").SetName("Keccak-224-0bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 224 }).Returns("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8").SetName("Keccak-224-24bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 224 }).Returns("e51faa2b4655150b931ee8d700dc202f763ca5f962c529eae55012b6").SetName("Keccak-224-448bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 224 }).Returns("344298994b1b06873eae2ce739c425c47291a2e24189e01b524f88dc").SetName("Keccak-224-896bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 224 }).Returns("19f9167be2a04c43abd0ed554788101b9c339031acc8e1468531303f").SetName("Keccak-224-AOneMillion"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 224 }).Returns("c42e4aee858e1a8ad2976896b9d23dd187f64436ee15969afdbc68c5").SetName("Keccak-224-GigaByte of Data"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 256 }).Returns("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").SetName("Keccak-256-0bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 256 }).Returns("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45").SetName("Keccak-256-24bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 256 }).Returns("45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371").SetName("Keccak-256-448bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 256 }).Returns("f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67").SetName("Keccak-256-896bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 256 }).Returns("fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96").SetName("Keccak-256-AOneMillion"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 256 }).Returns("5f313c39963dcf792b5470d4ade9f3a356a3e4021748690a958372e2b06f82a4").SetName("Keccak-256-GigaByte of Data"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 384 }).Returns("2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff").SetName("Keccak-384-0bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 384 }).Returns("f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e").SetName("Keccak-384-24bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 384 }).Returns("b41e8896428f1bcbb51e17abd6acc98052a3502e0d5bf7fa1af949b4d3c855e7c4dc2c390326b3f3e74c7b1e2b9a3657").SetName("Keccak-384-448bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 384 }).Returns("cc063f34685135368b34f7449108f6d10fa727b09d696ec5331771da46a923b6c34dbd1d4f77e595689c1f3800681c28").SetName("Keccak-384-896bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 384 }).Returns("0c8324e1ebc182822c5e2a086cac07c2fe00e3bce61d01ba8ad6b71780e2dec5fb89e5ae90cb593e57bc6258fdd94e17").SetName("Keccak-384-AOneMillion"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 384 }).Returns("9b7168b4494a80a86408e6b9dc4e5a1837c85dd8ff452ed410f2832959c08c8c0d040a892eb9a755776372d4a8732315").SetName("Keccak-384-GigaByte of Data"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 512 }).Returns("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e").SetName("Keccak-512-0bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 512 }).Returns("18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96").SetName("Keccak-512-24bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 512 }).Returns("6aa6d3669597df6d5a007b00d09c20795b5c4218234e1698a944757a488ecdc09965435d97ca32c3cfed7201ff30e070cd947f1fc12b9d9214c467d342bcba5d").SetName("Keccak-512-448bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 512 }).Returns("ac2fb35251825d3aa48468a9948c0a91b8256f6d97d8fa4160faff2dd9dfcc24f3f1db7a983dad13d53439ccac0b37e24037e7b95f80f59f37a2f683c4ba4682").SetName("Keccak-512-896bits"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 512 }).Returns("5cf53f2e556be5a624425ede23d0e8b2c7814b4ba0e4e09cbbf3c2fac7056f61e048fc341262875ebc58a5183fea651447124370c1ebf4d6c89bc9a7731063bb").SetName("Keccak-512-AOneMillion"));
            KeccakTestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 512 }).Returns("3e122edaf37398231cfaca4c7c216c9d66d5b899ec1d7ac617c40c7261906a45fc01617a021e5da3bd8d4182695b5cb785a28237cbb167590e34718e56d8aab8").SetName("Keccak-512-GigaByte of Data"));
        }

        private void SetupSha3Cases()
        {

            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 224 }).Returns("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7").SetName("SHA-3-224-0bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 224 }).Returns("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf").SetName("SHA-3-224-24bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 224 }).Returns("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33").SetName("SHA-3-224-448bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 224 }).Returns("543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc").SetName("SHA-3-224-896bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 224 }).Returns("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c").SetName("SHA-3-224-AOneMillion"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 224 }).Returns("c6d66e77ae289566afb2ce39277752d6da2a3c46010f1e0a0970ff60").SetName("SHA-3-224-GigaByte of Data"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 256 }).Returns("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").SetName("SHA-3-256-0bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 256 }).Returns("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532").SetName("SHA-3-256-24bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 256 }).Returns("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376").SetName("SHA-3-256-448bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 256 }).Returns("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18").SetName("SHA-3-256-896bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 256 }).Returns("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1").SetName("SHA-3-256-AOneMillion"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 256 }).Returns("ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b").SetName("SHA-3-256-GigaByte of Data"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 384 }).Returns("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004").SetName("SHA-3-384-0bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 384 }).Returns("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25").SetName("SHA-3-384-24bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 384 }).Returns("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22").SetName("SHA-3-384-448bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 384 }).Returns("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7").SetName("SHA-3-384-896bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 384 }).Returns("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340").SetName("SHA-3-384-AOneMillion"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 384 }).Returns("a04296f4fcaae14871bb5ad33e28dcf69238b04204d9941b8782e816d014bcb7540e4af54f30d578f1a1ca2930847a12").SetName("SHA-3-384-GigaByte of Data"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "", BitLength = 512 }).Returns("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26").SetName("SHA-3-512-0bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abc", BitLength = 512 }).Returns("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0").SetName("SHA-3-512-24bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", BitLength = 512 }).Returns("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e").SetName("SHA-3-512-448bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", BitLength = 512 }).Returns("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185").SetName("SHA-3-512-896bits"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputMessage = OneMillionA, BitLength = 512 }).Returns("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87").SetName("SHA-3-512-AOneMillion"));
            Sha3TestDataValues.Add(new TestCaseData(new TestDataValues() { InputBytes = GigaByte, BitLength = 512 }).Returns("235ffd53504ef836a1342b488f483b396eabbfe642cf78ee0d31feec788b23d0d18d5c339550dd5958a500d4b95363da1b5fa18affc1bab2292dc63b7d85097c").SetName("SHA-3-512-GigaByte of Data"));

        }

        public static IEnumerable<TestCaseData> ReturnSHA3TestCases()
        {
            foreach (var sha3TestDataValue in SetupSingleTestSharedData.Sha3TestDataValues)
            {
                yield return sha3TestDataValue;
            }
        }

        public static IEnumerable<TestCaseData> ReturnKeccakTestCases()
        {
            foreach (var KeccakTestDataValue in SetupSingleTestSharedData.KeccakTestDataValues)
            {
                yield return KeccakTestDataValue;
            }
        }
    }
}
