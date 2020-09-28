using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using SHA3Core.Enums;
using SHA3Core.Keccak;

namespace BenchMarks
{
    class Program
    {
        static void Main(string[] args)
        {

            startup();

            var summary = BenchmarkRunner.Run<RunBenchmarks>();
            new RunBenchmarks().KeccakDotNetWitHelper();
            //new RunBenchmarks().KeccakDotNetNoHelper();
            
        }

        public static byte[] _holyshit = new byte[1073741824];

        private static void startup()
        {
            byte[] tester = Encoding.ASCII.GetBytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");



            int lastDestination = 0;

            for (int i = 0; i < 16777216; i++)
            {

                Array.Copy(tester, 0, _holyshit, lastDestination, tester.Length);
                lastDestination += tester.Length;
            }
        }
    }

    public class RunBenchmarks
    {

        //private byte[] _holyshit = new byte[1073741824];

        //private readonly byte[] _encodedBytes;
        //string sentence = "“The French are certainly misunderstood: — but whether the fault is theirs, in not sufficiently explaining themselves, or speaking with that exact limitation and precision which one would expect on a point of such importance, and which, moreover, is so likely to be contested by us — or whether the fault may not be altogether on our side, in not understanding their language always so critically as to know “what they would be at” — I shall not decide; but ‘tis evident to me, when they affirm, “That they who have seen Paris, have seen every thing,” they must mean to speak of those who have seen it by day-light.”LL";
        public RunBenchmarks()
        {
            

            //var sentence = "Test";
            //var sentence = "absolut";

            //_encodedBytes = Encoding.ASCII.GetBytes(sentence);
        }

       

        //[Benchmark]
        //public void KeccakDotNetNoHelper()
        //{
        //    var keccack = new Keccak1600(72, 64, HashType.Keccak);

        //    keccack.Initialize();
        //    keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
        //    keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

        //    var byteResult = keccack.Squeeze();
        //    var result = BitConverter.ToString(byteResult).Replace("-", string.Empty);
        //}

        [Benchmark]
        public void KeccakDotNetWitHelper()
        {
            //var keccack = new Keccak1600(72, 64, HashType.Keccak);

            var keccack = new Keccak(KeccakBitType.K256);

            var result = keccack.Hash(Program._holyshit);
            //var sha = new SHA3(SHA3BitType.S512);

            //var result =  sha.Hash(Program._holyshit);



            //keccack.Initialize();
            //keccack.Absorb(_encodedBytes, 0, _encodedBytes.Length);
            //keccack.Partial(_encodedBytes, 0, _encodedBytes.Length);

            //var byteResult = keccack.Squeeze();
            //var result = BitConverter.ToString(byteResult).Replace("-", string.Empty);
        }


    }
}
