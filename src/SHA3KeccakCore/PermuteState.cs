namespace SHA3Core
{
    public class PermuteState
    {
        public ulong A00;
        public ulong A01;
        public ulong A02;
        public ulong A03;
        public ulong A04;
        public ulong A05;
        public ulong A06;
        public ulong A07;
        public ulong A08;
        public ulong A09;
        public ulong A10;
        public ulong A11;
        public ulong A12;
        public ulong A13;
        public ulong A14;
        public ulong A15;
        public ulong A16;
        public ulong A17;
        public ulong A18;
        public ulong A19;
        public ulong A20;
        public ulong A21;
        public ulong A22;
        public ulong A23;
        public ulong A24;

        public ulong C0;
        public ulong C1;

        public void Load(ulong[] state)
        {
            A00 = state[0]; A01 = state[1]; A02 = state[2]; A03 = state[3]; A04 = state[4];
            A05 = state[5]; A06 = state[6]; A07 = state[7]; A08 = state[8]; A09 = state[9];
            A10 = state[10]; A11 = state[11]; A12 = state[12]; A13 = state[13]; A14 = state[14];
            A15 = state[15]; A16 = state[16]; A17 = state[17]; A18 = state[18]; A19 = state[19];
            A20 = state[20]; A21 = state[21]; A22 = state[22]; A23 = state[23]; A24 = state[24];
        }

        public ulong[] SetState(ulong[] state)
        {
            state[0] = A00; state[1] = A01; state[2] = A02; state[3] = A03; state[4] = A04;
            state[5] = A05; state[6] = A06; state[7] = A07; state[8] = A08; state[9] = A09;
            state[10] = A10; state[11] = A11; state[12] = A12; state[13] = A13; state[14] = A14;
            state[15] = A15; state[16] = A16; state[17] = A17; state[18] = A18; state[19] = A19;
            state[20] = A20; state[21] = A21; state[22] = A22; state[23] = A23; state[24] = A24;

            return state;
        }
    }
}
