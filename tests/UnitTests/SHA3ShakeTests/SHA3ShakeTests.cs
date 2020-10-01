using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using SHA3Core.Enums;
using SHA3Core.SHA3;


namespace UnitTests.SHA3ShakeTests
{
    public class SHA3ShakeTests
    {

        [TestCaseSource(typeof(SetupTestSharedData), "ReturnShakeTestCases"), Parallelizable(ParallelScope.Children)]
        public string SHA3ShakeTester(TestDataValues testDataValues)
        {
            var sha3 = new SHA3Shake((ShakeBitType)(testDataValues.BitLength));
            var result = testDataValues.InputMessage == null ? sha3.Hash(testDataValues.InputBytes) : sha3.Hash(testDataValues.InputMessage);

            return result;
        }
    }
}
