using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SHA3KeccakCore
{
    public class Keccak1600
    {
        /// <summary>
        /// The number of Keccak rounds.
        /// </summary>
        private const int _keccakRounds = 24;
        /// <summary>
        /// The rate in bytes of the sponge state.
        /// </summary>
        private readonly int _rateBytes;
        /// <summary>
        /// The output length of the hash.
        /// </summary>
        private readonly int _outputLength;
        /// <summary>
        /// The state block size.
        /// </summary>
        private int _blockSize;
        /// <summary>
        /// The state.
        /// </summary>
        private ulong[] _state;

        /// <summary>
        /// The hash result.
        /// </summary>
        private byte[] _result;

        private readonly int _hashType;

        private byte[] _extracted;

        public Keccak1600(int rateBytes, int outputLength, HashType hashType)
        {
            _rateBytes = rateBytes;
            _outputLength = outputLength;
            _hashType = (int)hashType;
        }


        public void Initialize()
        {
            _blockSize = default;
            _state = new ulong[25];
            _result = new byte[_outputLength];
            _extracted = new byte[_rateBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Absorb(byte[] array, int start, int size)
        {
            var offSet = 0;
            while (size > 0)
            {
                _blockSize = Math.Min(size, _rateBytes);
                for (var i = start; i < _blockSize / 8; i++)
                {
                    _state[i] ^= AddStateBuffer(array, offSet);
                    offSet += 8;
                }

                size -= _blockSize;

                if (_blockSize != _rateBytes) continue;
                Permute(_state);
                _blockSize = 0;
            }
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Partial(byte[] array, int start, int size)
        {
            var mod = size % 72;
            var finalRound = mod / 8;
            var mod2 = mod % 8;
            var partial = new byte[8];

            Array.Copy(array, size - mod2, partial, 0, mod2);
            partial[mod2] = (byte)_hashType;
            _state[finalRound] ^= AddStateBuffer(partial, 0);

            _state[8] ^= (1UL << 63);

            Permute(_state);

            Extract();
        }



        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal ulong AddStateBuffer(byte[] bs, int off)
        {
            var result = bs[off]
                | (ulong)bs[off + 1] << 8
                | (ulong)bs[off + 2] << 16
                | (ulong)bs[off + 3] << 24
                | (ulong)bs[off + 4] << 32
                | (ulong)bs[off + 5] << 40
                | (ulong)bs[off + 6] << 48
                | (ulong)bs[off + 7] << 56;

            return result;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Extract()
        {
            var offset = 0;
            for (var i = 0; i < _extracted.Length / 8; i++)
            {
                ExtractStateBuffer(_state[i], _extracted, offset);
                offset += 8;
            }
        }

        internal void ExtractStateBuffer(ulong n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
            bs[off + 4] = (byte)(n >> 32);
            bs[off + 5] = (byte)(n >> 40);
            bs[off + 6] = (byte)(n >> 48);
            bs[off + 7] = (byte)(n >> 56);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte[] Squeeze()
        {
            var outputBytesLeft = _outputLength;

            while (outputBytesLeft > 0)
            {
                _blockSize = Math.Min(outputBytesLeft, _rateBytes);
                Array.Copy(_extracted, 0, _result, 0, _blockSize);
                //_result = MarshalCopy(_extracted, _blockSize);
                outputBytesLeft -= _blockSize;

                if (outputBytesLeft <= 0) continue;
                Permute(_state);
            }

            return _result;
        }

        private byte[] MarshalCopy(byte[] sourceBytes, int length)
        {
            int size = Marshal.SizeOf(sourceBytes[0] * sourceBytes.Length);

            IntPtr pnt = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.Copy(sourceBytes, 0, pnt, sourceBytes.Length);

                byte[] destination = new byte[length];

                Marshal.Copy(pnt, destination, 0, length);

                return destination;

            }
            catch (Exception ex)
            {

                Console.WriteLine(ex);
                throw;

            }
            finally
            {
                Marshal.FreeHGlobal(pnt);
            }


        }

        /// <summary>
        /// The Iota permutation round constants.
        /// </summary>
        private readonly ulong[] RoundConstants = new ulong[]
        {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Permute(ulong[] state)
        {
            ulong C0, C1;

            ulong a00 = state[0], a01 = state[1], a02 = state[2], a03 = state[3], a04 = state[4];
            ulong a05 = state[5], a06 = state[6], a07 = state[7], a08 = state[8], a09 = state[9];
            ulong a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14];
            ulong a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19];
            ulong a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];

            for (int round = 0; round < _keccakRounds; round++)
            {
                Theta();
                RhoPi();
                Chi();
                Iota(round);
            }

            void Theta()
            {
                C0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
                C1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
                var C2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
                var C3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
                var C4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

                var D0 = ShiftULongLeft(C1, 1) ^ C4;
                var D1 = ShiftULongLeft(C2, 1) ^ C0;
                var D2 = ShiftULongLeft(C3, 1) ^ C1;
                var D3 = ShiftULongLeft(C4, 1) ^ C2;
                var D4 = ShiftULongLeft(C0, 1) ^ C3;

                a00 ^= D0;
                a05 ^= D0;
                a10 ^= D0;
                a15 ^= D0;
                a20 ^= D0;
                a01 ^= D1;
                a06 ^= D1;
                a11 ^= D1;
                a16 ^= D1;
                a21 ^= D1;
                a02 ^= D2;
                a07 ^= D2;
                a12 ^= D2;
                a17 ^= D2;
                a22 ^= D2;
                a03 ^= D3;
                a08 ^= D3;
                a13 ^= D3;
                a18 ^= D3;
                a23 ^= D3;
                a04 ^= D4;
                a09 ^= D4;
                a14 ^= D4;
                a19 ^= D4;
                a24 ^= D4;

            }

            //void Theta()
            //{
            //    C0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
            //    C1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
            //    C2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
            //    C3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
            //    C4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

            //    D0 = ShiftULongLeft(C1, 1) ^ C4;
            //    D1 = ShiftULongLeft(C2, 1) ^ C0;
            //    D2 = ShiftULongLeft(C3, 1) ^ C1;
            //    D3 = ShiftULongLeft(C4, 1) ^ C2;
            //    D4 = ShiftULongLeft(C0, 1) ^ C3;

            //    state[00] ^= D0;
            //    state[05] ^= D0;
            //    state[10] ^= D0;
            //    state[15] ^= D0;
            //    state[20] ^= D0;
            //    state[01] ^= D1;
            //    state[06] ^= D1;
            //    state[11] ^= D1;
            //    state[16] ^= D1;
            //    state[21] ^= D1;
            //    state[02] ^= D2;
            //    state[07] ^= D2;
            //    state[12] ^= D2;
            //    state[17] ^= D2;
            //    state[22] ^= D2;
            //    state[03] ^= D3;
            //    state[08] ^= D3;
            //    state[13] ^= D3;
            //    state[18] ^= D3;
            //    state[23] ^= D3;
            //    state[04] ^= D4;
            //    state[09] ^= D4;
            //    state[14] ^= D4;
            //    state[19] ^= D4;
            //    state[24] ^= D4;
            //}

            void RhoPi()
            {
                C1 = ShiftULongLeft(a01, 1);

                a01 = ShiftULongLeft(a06, 44);
                a06 = ShiftULongLeft(a09, 20);
                a09 = ShiftULongLeft(a22, 61);
                a22 = ShiftULongLeft(a14, 39);
                a14 = ShiftULongLeft(a20, 18);
                a20 = ShiftULongLeft(a02, 62);
                a02 = ShiftULongLeft(a12, 43);
                a12 = ShiftULongLeft(a13, 25);
                a13 = ShiftULongLeft(a19, 08);
                a19 = ShiftULongLeft(a23, 56);
                a23 = ShiftULongLeft(a15, 41);
                a15 = ShiftULongLeft(a04, 27);
                a04 = ShiftULongLeft(a24, 14);
                a24 = ShiftULongLeft(a21, 02);
                a21 = ShiftULongLeft(a08, 55);
                a08 = ShiftULongLeft(a16, 45);
                a16 = ShiftULongLeft(a05, 36);
                a05 = ShiftULongLeft(a03, 28);
                a03 = ShiftULongLeft(a18, 21);
                a18 = ShiftULongLeft(a17, 15);
                a17 = ShiftULongLeft(a11, 10);
                a11 = ShiftULongLeft(a07, 06);
                a07 = ShiftULongLeft(a10, 03);

                a10 = C1;

            }

            //void RhoPi()
            //{
            //    ulong A = ShiftULongLeft(state[1], 1);

            //    state[01] = ShiftULongLeft(state[06], 44);
            //    state[06] = ShiftULongLeft(state[09], 20);
            //    state[09] = ShiftULongLeft(state[22], 61);
            //    state[22] = ShiftULongLeft(state[14], 39);
            //    state[14] = ShiftULongLeft(state[20], 18);
            //    state[20] = ShiftULongLeft(state[02], 62);
            //    state[02] = ShiftULongLeft(state[12], 43);
            //    state[12] = ShiftULongLeft(state[13], 25);
            //    state[13] = ShiftULongLeft(state[19], 08);
            //    state[19] = ShiftULongLeft(state[23], 56);
            //    state[23] = ShiftULongLeft(state[15], 41);
            //    state[15] = ShiftULongLeft(state[04], 27);
            //    state[04] = ShiftULongLeft(state[24], 14);
            //    state[24] = ShiftULongLeft(state[21], 02);
            //    state[21] = ShiftULongLeft(state[08], 55);
            //    state[08] = ShiftULongLeft(state[16], 45);
            //    state[16] = ShiftULongLeft(state[05], 36);
            //    state[05] = ShiftULongLeft(state[03], 28);
            //    state[03] = ShiftULongLeft(state[18], 21);
            //    state[18] = ShiftULongLeft(state[17], 15);
            //    state[17] = ShiftULongLeft(state[11], 10);
            //    state[11] = ShiftULongLeft(state[07], 06);
            //    state[07] = ShiftULongLeft(state[10], 03);
            //    state[10] = A;
            //}

            void Chi()
            {
                C0 = a00 ^ (~a01 & a02);
                C1 = a01 ^ (~a02 & a03);
                a02 ^= ~a03 & a04;
                a03 ^= ~a04 & a00;
                a04 ^= ~a00 & a01;
                a00 = C0;
                a01 = C1;

                C0 = a05 ^ (~a06 & a07);
                C1 = a06 ^ (~a07 & a08);
                a07 ^= ~a08 & a09;
                a08 ^= ~a09 & a05;
                a09 ^= ~a05 & a06;
                a05 = C0;
                a06 = C1;

                C0 = a10 ^ (~a11 & a12);
                C1 = a11 ^ (~a12 & a13);
                a12 ^= ~a13 & a14;
                a13 ^= ~a14 & a10;
                a14 ^= ~a10 & a11;
                a10 = C0;
                a11 = C1;

                C0 = a15 ^ (~a16 & a17);
                C1 = a16 ^ (~a17 & a18);
                a17 ^= ~a18 & a19;
                a18 ^= ~a19 & a15;
                a19 ^= ~a15 & a16;
                a15 = C0;
                a16 = C1;

                C0 = a20 ^ (~a21 & a22);
                C1 = a21 ^ (~a22 & a23);
                a22 ^= ~a23 & a24;
                a23 ^= ~a24 & a20;
                a24 ^= ~a20 & a21;
                a20 = C0;
                a21 = C1;
            }

            //void Chi()
            //{
            //    for (int i = 0; i < 25; i += 5)
            //    {
            //        C0 = state[0 + i] ^ ((~state[1 + i]) & state[2 + i]);
            //        C1 = state[1 + i] ^ ((~state[2 + i]) & state[3 + i]);
            //        C2 = state[2 + i] ^ ((~state[3 + i]) & state[4 + i]);
            //        C3 = state[3 + i] ^ ((~state[4 + i]) & state[0 + i]);
            //        C4 = state[4 + i] ^ ((~state[0 + i]) & state[1 + i]);

            //        state[0 + i] = C0;
            //        state[1 + i] = C1;
            //        state[2 + i] = C2;
            //        state[3 + i] = C3;
            //        state[4 + i] = C4;
            //    }

            //C0 = state[0 + 0] ^ ((~state[1 + 0]) & state[2 + 0]);
            //C1 = state[1 + 0] ^ ((~state[2 + 0]) & state[3 + 0]);
            //C2 = state[2 + 0] ^ ((~state[3 + 0]) & state[4 + 0]);
            //C3 = state[3 + 0] ^ ((~state[4 + 0]) & state[0 + 0]);
            //C4 = state[4 + 0] ^ ((~state[0 + 0]) & state[1 + 0]);

            //state[0 + 0] = C0;
            //state[1 + 0] = C1;
            //state[2 + 0] = C2;
            //state[3 + 0] = C3;
            //state[4 + 0] = C4;

            //C0 = state[0 + 5] ^ ((~state[1 + 5]) & state[2 + 5]);
            //C1 = state[1 + 5] ^ ((~state[2 + 5]) & state[3 + 5]);
            //C2 = state[2 + 5] ^ ((~state[3 + 5]) & state[4 + 5]);
            //C3 = state[3 + 5] ^ ((~state[4 + 5]) & state[0 + 5]);
            //C4 = state[4 + 5] ^ ((~state[0 + 5]) & state[1 + 5]);

            //state[0 + 5] = C0;
            //state[1 + 5] = C1;
            //state[2 + 5] = C2;
            //state[3 + 5] = C3;
            //state[4 + 5] = C4;

            //C0 = state[0 + 10] ^ ((~state[1 + 10]) & state[2 + 10]);
            //C1 = state[1 + 10] ^ ((~state[2 + 10]) & state[3 + 10]);
            //C2 = state[2 + 10] ^ ((~state[3 + 10]) & state[4 + 10]);
            //C3 = state[3 + 10] ^ ((~state[4 + 10]) & state[0 + 10]);
            //C4 = state[4 + 10] ^ ((~state[0 + 10]) & state[1 + 10]);

            //state[0 + 10] = C0;
            //state[1 + 10] = C1;
            //state[2 + 10] = C2;
            //state[3 + 10] = C3;
            //state[4 + 10] = C4;

            //C0 = state[0 + 15] ^ ((~state[1 + 15]) & state[2 + 15]);
            //C1 = state[1 + 15] ^ ((~state[2 + 15]) & state[3 + 15]);
            //C2 = state[2 + 15] ^ ((~state[3 + 15]) & state[4 + 15]);
            //C3 = state[3 + 15] ^ ((~state[4 + 15]) & state[0 + 15]);
            //C4 = state[4 + 15] ^ ((~state[0 + 15]) & state[1 + 15]);

            //state[0 + 15] = C0;
            //state[1 + 15] = C1;
            //state[2 + 15] = C2;
            //state[3 + 15] = C3;
            //state[4 + 15] = C4;

            //C0 = state[0 + 20] ^ ((~state[1 + 20]) & state[2 + 20]);
            //C1 = state[1 + 20] ^ ((~state[2 + 20]) & state[3 + 20]);
            //C2 = state[2 + 20] ^ ((~state[3 + 20]) & state[4 + 20]);
            //C3 = state[3 + 20] ^ ((~state[4 + 20]) & state[0 + 20]);
            //C4 = state[4 + 20] ^ ((~state[0 + 20]) & state[1 + 20]);

            //state[0 + 20] = C0;
            //state[1 + 20] = C1;
            //state[2 + 20] = C2;
            //state[3 + 20] = C3;
            //state[4 + 20] = C4;


            //}

            void Iota(int round)
            {
                a00 ^= RoundConstants[round];
            }

            state[0] = a00; state[1] = a01; state[2] = a02; state[3] = a03; state[4] = a04;
            state[5] = a05; state[6] = a06; state[7] = a07; state[8] = a08; state[9] = a09;
            state[10] = a10; state[11] = a11; state[12] = a12; state[13] = a13; state[14] = a14;
            state[15] = a15; state[16] = a16; state[17] = a17; state[18] = a18; state[19] = a19;
            state[20] = a20; state[21] = a21; state[22] = a22; state[23] = a23; state[24] = a24;
        }

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //private void Permute(ulong[] state)
        //{
        //    ulong a00 = state[0], a01 = state[1], a02 = state[2], a03 = state[3], a04 = state[4];
        //    ulong a05 = state[5], a06 = state[6], a07 = state[7], a08 = state[8], a09 = state[9];
        //    ulong a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14];
        //    ulong a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19];
        //    ulong a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];

        //    for (int i = 0; i < 24; i++)
        //    {
        //        // theta
        //        ulong c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
        //        ulong c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
        //        ulong c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
        //        ulong c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
        //        ulong c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

        //        ulong d1 = (c1 << 1 | c1 >> -1) ^ c4;
        //        ulong d2 = (c2 << 1 | c2 >> -1) ^ c0;
        //        ulong d3 = (c3 << 1 | c3 >> -1) ^ c1;
        //        ulong d4 = (c4 << 1 | c4 >> -1) ^ c2;
        //        ulong d0 = (c0 << 1 | c0 >> -1) ^ c3;

        //        a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
        //        a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
        //        a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
        //        a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
        //        a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

        //        // rho/pi
        //        c1 = a01 << 1 | a01 >> 63;
        //        a01 = a06 << 44 | a06 >> 20;
        //        a06 = a09 << 20 | a09 >> 44;
        //        a09 = a22 << 61 | a22 >> 3;
        //        a22 = a14 << 39 | a14 >> 25;
        //        a14 = a20 << 18 | a20 >> 46;
        //        a20 = a02 << 62 | a02 >> 2;
        //        a02 = a12 << 43 | a12 >> 21;
        //        a12 = a13 << 25 | a13 >> 39;
        //        a13 = a19 << 8 | a19 >> 56;
        //        a19 = a23 << 56 | a23 >> 8;
        //        a23 = a15 << 41 | a15 >> 23;
        //        a15 = a04 << 27 | a04 >> 37;
        //        a04 = a24 << 14 | a24 >> 50;
        //        a24 = a21 << 2 | a21 >> 62;
        //        a21 = a08 << 55 | a08 >> 9;
        //        a08 = a16 << 45 | a16 >> 19;
        //        a16 = a05 << 36 | a05 >> 28;
        //        a05 = a03 << 28 | a03 >> 36;
        //        a03 = a18 << 21 | a18 >> 43;
        //        a18 = a17 << 15 | a17 >> 49;
        //        a17 = a11 << 10 | a11 >> 54;
        //        a11 = a07 << 6 | a07 >> 58;
        //        a07 = a10 << 3 | a10 >> 61;
        //        a10 = c1;

        //        // chi
        //        c0 = a00 ^ (~a01 & a02);
        //        c1 = a01 ^ (~a02 & a03);
        //        a02 ^= ~a03 & a04;
        //        a03 ^= ~a04 & a00;
        //        a04 ^= ~a00 & a01;
        //        a00 = c0;
        //        a01 = c1;

        //        c0 = a05 ^ (~a06 & a07);
        //        c1 = a06 ^ (~a07 & a08);
        //        a07 ^= ~a08 & a09;
        //        a08 ^= ~a09 & a05;
        //        a09 ^= ~a05 & a06;
        //        a05 = c0;
        //        a06 = c1;

        //        c0 = a10 ^ (~a11 & a12);
        //        c1 = a11 ^ (~a12 & a13);
        //        a12 ^= ~a13 & a14;
        //        a13 ^= ~a14 & a10;
        //        a14 ^= ~a10 & a11;
        //        a10 = c0;
        //        a11 = c1;

        //        c0 = a15 ^ (~a16 & a17);
        //        c1 = a16 ^ (~a17 & a18);
        //        a17 ^= ~a18 & a19;
        //        a18 ^= ~a19 & a15;
        //        a19 ^= ~a15 & a16;
        //        a15 = c0;
        //        a16 = c1;

        //        c0 = a20 ^ (~a21 & a22);
        //        c1 = a21 ^ (~a22 & a23);
        //        a22 ^= ~a23 & a24;
        //        a23 ^= ~a24 & a20;
        //        a24 ^= ~a20 & a21;
        //        a20 = c0;
        //        a21 = c1;

        //        // iota
        //        a00 ^= RoundConstants[i];
        //    }

        //    state[0] = a00; state[1] = a01; state[2] = a02; state[3] = a03; state[4] = a04;
        //    state[5] = a05; state[6] = a06; state[7] = a07; state[8] = a08; state[9] = a09;
        //    state[10] = a10; state[11] = a11; state[12] = a12; state[13] = a13; state[14] = a14;
        //    state[15] = a15; state[16] = a16; state[17] = a17; state[18] = a18; state[19] = a19;
        //    state[20] = a20; state[21] = a21; state[22] = a22; state[23] = a23; state[24] = a24;
        //}


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong ShiftULongLeft(ulong x, byte y) => (x << y) | (x >> (64 - y));
    }
}
