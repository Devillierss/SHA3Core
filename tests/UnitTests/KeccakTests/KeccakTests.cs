using NUnit.Framework;
using SHA3Core.Enums;
using SHA3Core.Keccak;

namespace UnitTests.KeccakTests
{
    public class KeccakTests
    {
        
        [TestCaseSource(typeof(SetupTestSharedData), "ReturnKeccakTestCases"), Parallelizable(ParallelScope.Children)]
        public string KeccakTester(TestDataValues testDataValues)
        {
            var sha3 = new Keccak((KeccakBitType)(testDataValues.BitLength));
            var result = testDataValues.InputMessage == null ? sha3.Hash(testDataValues.InputBytes) : sha3.Hash(testDataValues.InputMessage);

            return result;
        }

    }
}