using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SHA3KeccakCore
{
    public class Keccak1600
    {
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

        public Keccak1600(KeccakConfiguration configuration)
        {
            _rateBytes = configuration.RateBytes;
            _outputLength = configuration.OutputLength;
            _hashType = (int)configuration.HashType;
        }

        public void Initialize()
        {
            _blockSize = default;
            _state = new ulong[25];
            _result = new byte[_outputLength];
            _extracted = new byte[_rateBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected void Absorb(byte[] array, int start, int size)
        {
            var offSet = 0;
            while (size > 0)
            {
                _blockSize = Math.Min(size, _rateBytes);
                for (var i = start; i < _blockSize / 8; i++)
                {
                    _state[i] ^= KeccakPermuteHelpers.AddStateBuffer(array, offSet);
                    offSet += 8;
                }

                size -= _blockSize;

                if (_blockSize != _rateBytes) continue;
                KeccakPermuteHelpers.Permute(_state);
                _blockSize = 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected void Partial(byte[] array, int start, int size)
        {
            var mod = size % 72;
            var finalRound = mod / 8;
            var mod2 = mod % 8;
            var partial = new byte[8];

            //Buffer.BlockCopy(array, size - mod2, partial, 0, mod2);
            Array.Copy(array, size - mod2, partial, 0, mod2);
            partial[mod2] = (byte)_hashType;
            _state[finalRound] ^= KeccakPermuteHelpers.AddStateBuffer(partial, 0);

            _state[8] ^= (1UL << 63);

            KeccakPermuteHelpers.Permute(_state);

            KeccakPermuteHelpers.Extract(_extracted, _state);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected byte[] Squeeze()
        {
            var outputBytesLeft = _outputLength;

            while (outputBytesLeft > 0)
            {
                _blockSize = Math.Min(outputBytesLeft, _rateBytes);
                //Buffer.BlockCopy(_extracted, 0, _result, 0, _blockSize);
                Array.Copy(_extracted, 0, _result, 0, _blockSize);
                //_result = MarshalCopy(_extracted, _blockSize);
                outputBytesLeft -= _blockSize;

                if (outputBytesLeft <= 0) continue;
                KeccakPermuteHelpers.Permute(_state);
            }

            return _result;
        }

    }
}
