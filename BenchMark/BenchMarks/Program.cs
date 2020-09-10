using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using SHA3KeccakCore;

namespace BenchMarks
{
    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<RunBenchmarks>();
            new RunBenchmarks().KeccakDotNet();
        }
    }

    public class RunBenchmarks
    {

        private readonly byte[] _encodedBytes;

        public RunBenchmarks()
        {
            const string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";
            //var sentence = "Test";
            //var sentence = "absolut";

            _encodedBytes = Encoding.ASCII.GetBytes(sentence);
        }

        [Benchmark]
        public void KeccakDotNet()
        {
            var keccack = new Keccak1600(72, 64, HashType.Keccak);

            keccack.Initialize();
            keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
            keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

            var byteResult = keccack.Squeeze();
            var result = BitConverter.ToString(byteResult).Replace("-", string.Empty);
        }
    }
}
