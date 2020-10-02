using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using NUnit.Framework;
using NUnit.Framework.Internal;
using SHA3Core;
using SHA3Core.Enums;
using SHA3Core.SHA3;

namespace UnitTests.SHA3Tests
{
    public class SHA3Tests
    {

        [TestCaseSource(typeof(SetupTestSharedData), "ReturnSHA3TestCases"), Parallelizable(ParallelScope.Children)]
        public string SHA3Tester(TestDataValues testDataValues)
        {
            var sha3 = new SHA3((SHA3BitType)(testDataValues.BitLength));
            var result = testDataValues.InputMessage == null ? sha3.Hash(testDataValues.InputBytes) : sha3.Hash(testDataValues.InputMessage);


            return result;

        }
    }
}
