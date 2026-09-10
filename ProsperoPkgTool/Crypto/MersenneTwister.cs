namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Clean-room MT19937 Mersenne Twister, implemented from the public-domain Matsumoto &amp; Nishimura
/// reference algorithm (2002), including the standard <c>init_by_array</c> array seeding. It exists
/// only to reproduce the deterministic RSA-PKCS#1 v1.5 non-zero padding stream that the publishing
/// tools derive from <c>SHA-256(modulus || data)</c>; the default seed matches the classic public
/// implementation (<c>19650218</c>).
/// </summary>
internal sealed class MersenneTwister
{
    private const int N = 624;
    private const int M = 397;
    private const uint MatrixA = 0x9908B0DF;
    private const uint UpperMask = 0x80000000;
    private const uint LowerMask = 0x7FFFFFFF;
    private const uint DefaultSeed = 19650218;

    private readonly uint[] _mt = new uint[N];
    private int _mti;

    /// <summary>Seeds the generator from an array of 32-bit words (<c>init_by_array</c>).</summary>
    public MersenneTwister(ReadOnlySpan<uint> seed)
    {
        InitGenrand(DefaultSeed);

        int i = 1, j = 0;
        for (int k = Math.Max(N, seed.Length); k > 0; k--)
        {
            _mt[i] = (_mt[i] ^ ((_mt[i - 1] ^ (_mt[i - 1] >> 30)) * 1664525u)) + seed[j] + (uint)j;
            i++;
            j++;
            if (i >= N) { _mt[0] = _mt[N - 1]; i = 1; }
            if (j >= seed.Length) j = 0;
        }
        for (int k = N - 1; k > 0; k--)
        {
            _mt[i] = (_mt[i] ^ ((_mt[i - 1] ^ (_mt[i - 1] >> 30)) * 1566083941u)) - (uint)i;
            i++;
            if (i >= N) { _mt[0] = _mt[N - 1]; i = 1; }
        }
        _mt[0] = 0x80000000u;
    }

    private void InitGenrand(uint seed)
    {
        _mt[0] = seed;
        for (int i = 1; i < N; i++)
            _mt[i] = 1812433253u * (_mt[i - 1] ^ (_mt[i - 1] >> 30)) + (uint)i;
        _mti = N;
    }

    /// <summary>Returns the next tempered 32-bit word (<c>genrand_int32</c>).</summary>
    public uint NextUInt32()
    {
        if (_mti >= N)
        {
            int kk;
            for (kk = 0; kk < N - M; kk++)
            {
                uint y = (_mt[kk] & UpperMask) | (_mt[kk + 1] & LowerMask);
                _mt[kk] = _mt[kk + M] ^ (y >> 1) ^ ((y & 1) != 0 ? MatrixA : 0u);
            }
            for (; kk < N - 1; kk++)
            {
                uint y = (_mt[kk] & UpperMask) | (_mt[kk + 1] & LowerMask);
                _mt[kk] = _mt[kk + (M - N)] ^ (y >> 1) ^ ((y & 1) != 0 ? MatrixA : 0u);
            }
            uint y2 = (_mt[N - 1] & UpperMask) | (_mt[0] & LowerMask);
            _mt[N - 1] = _mt[M - 1] ^ (y2 >> 1) ^ ((y2 & 1) != 0 ? MatrixA : 0u);
            _mti = 0;
        }

        uint x = _mt[_mti++];
        x ^= x >> 11;
        x ^= (x << 7) & 0x9D2C5680u;
        x ^= (x << 15) & 0xEFC60000u;
        x ^= x >> 18;
        return x;
    }
}
