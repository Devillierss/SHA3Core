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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Permute(ulong[] state)
        {
            ulong C0, C1, C2, C3, C4, D0, D1, D2, D3, D4;

            for (int round = 0; round < _keccakRounds; round++)
            {
                Theta();
                RhoPi();
                Chi();
                Iota(round);
            }

            void Theta()
            {
                C0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
                C1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
                C2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
                C3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
                C4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

                D0 = ShiftULongLeft(C1, 1) ^ C4;
                D1 = ShiftULongLeft(C2, 1) ^ C0;
                D2 = ShiftULongLeft(C3, 1) ^ C1;
                D3 = ShiftULongLeft(C4, 1) ^ C2;
                D4 = ShiftULongLeft(C0, 1) ^ C3;

                state[00] ^= D0;
                state[05] ^= D0;
                state[10] ^= D0;
                state[15] ^= D0;
                state[20] ^= D0;
                state[01] ^= D1;
                state[06] ^= D1;
                state[11] ^= D1;
                state[16] ^= D1;
                state[21] ^= D1;
                state[02] ^= D2;
                state[07] ^= D2;
                state[12] ^= D2;
                state[17] ^= D2;
                state[22] ^= D2;
                state[03] ^= D3;
                state[08] ^= D3;
                state[13] ^= D3;
                state[18] ^= D3;
                state[23] ^= D3;
                state[04] ^= D4;
                state[09] ^= D4;
                state[14] ^= D4;
                state[19] ^= D4;
                state[24] ^= D4;
            }

            void RhoPi()
            {
                ulong A = ShiftULongLeft(state[1], 1);

                state[01] = ShiftULongLeft(state[06], 44);
                state[06] = ShiftULongLeft(state[09], 20);
                state[09] = ShiftULongLeft(state[22], 61);
                state[22] = ShiftULongLeft(state[14], 39);
                state[14] = ShiftULongLeft(state[20], 18);
                state[20] = ShiftULongLeft(state[02], 62);
                state[02] = ShiftULongLeft(state[12], 43);
                state[12] = ShiftULongLeft(state[13], 25);
                state[13] = ShiftULongLeft(state[19], 08);
                state[19] = ShiftULongLeft(state[23], 56);
                state[23] = ShiftULongLeft(state[15], 41);
                state[15] = ShiftULongLeft(state[04], 27);
                state[04] = ShiftULongLeft(state[24], 14);
                state[24] = ShiftULongLeft(state[21], 02);
                state[21] = ShiftULongLeft(state[08], 55);
                state[08] = ShiftULongLeft(state[16], 45);
                state[16] = ShiftULongLeft(state[05], 36);
                state[05] = ShiftULongLeft(state[03], 28);
                state[03] = ShiftULongLeft(state[18], 21);
                state[18] = ShiftULongLeft(state[17], 15);
                state[17] = ShiftULongLeft(state[11], 10);
                state[11] = ShiftULongLeft(state[07], 06);
                state[07] = ShiftULongLeft(state[10], 03);
                state[10] = A;
            }

            void Chi()
            {
                for (int i = 0; i < 25; i += 5)
                {
                    C0 = state[0 + i] ^ ((~state[1 + i]) & state[2 + i]);
                    C1 = state[1 + i] ^ ((~state[2 + i]) & state[3 + i]);
                    C2 = state[2 + i] ^ ((~state[3 + i]) & state[4 + i]);
                    C3 = state[3 + i] ^ ((~state[4 + i]) & state[0 + i]);
                    C4 = state[4 + i] ^ ((~state[0 + i]) & state[1 + i]);

                    state[0 + i] = C0;
                    state[1 + i] = C1;
                    state[2 + i] = C2;
                    state[3 + i] = C3;
                    state[4 + i] = C4;
                }

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


            }

            void Iota(int round)
            {
                state[0] ^= RoundConstants[round];
            }
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong ShiftULongLeft(ulong x, byte y) => (x << y) | (x >> (64 - y));
    }
}
