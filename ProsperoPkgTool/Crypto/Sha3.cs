using System.Buffers.Binary;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Minimal SHA3-256 (FIPS 202, Keccak padding domain 0x06) implementation.
///
/// .NET does not ship a built-in SHA3 implementation, so this clean-room
/// Keccak-f[1600] permutation is provided for the PS5 package crypto, which is
/// built almost entirely on SHA3-256. Written from the public Keccak reference
/// (Keccak team) sponge construction; no third-party code is used.
/// </summary>
public static class Sha3
{
    private const int StateSizeBytes = 200;            // 1600-bit state
    private const int RateBytes = 136;                 // SHA3-256 rate = 1088 bits
    private const int DigestSizeBytes = 32;            // 256-bit digest
    private const byte DomainSuffix = 0x06;            // FIPS 202 SHA3 (not raw Keccak 0x01)

    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    ];

    // Rotation offsets r[x,y] indexed as x + 5*y.
    private static readonly int[] RotationOffsets =
    [
         0, 36,  3, 41, 18,
         1, 44, 10, 45,  2,
        62,  6, 43, 15, 61,
        28, 55, 25, 21, 56,
        27, 20, 39,  8, 14,
    ];

    public static byte[] Sha3_256(ReadOnlySpan<byte> data)
    {
        // Prefer the platform SHA3-256 (native, an order of magnitude faster); the clean-room Keccak
        // below is the fallback on platforms without an OS/BCL implementation. Both emit the identical
        // FIPS 202 digest.
        if (System.Security.Cryptography.SHA3_256.IsSupported)
        {
            byte[] digest = new byte[DigestSizeBytes];
            System.Security.Cryptography.SHA3_256.HashData(data, digest);
            return digest;
        }
        return ManagedSha3_256(data);
    }

    private static byte[] ManagedSha3_256(ReadOnlySpan<byte> data)
    {
        Span<byte> state = stackalloc byte[StateSizeBytes];
        state.Clear();

        // Absorb full rate-sized blocks.
        int offset = 0;
        while (offset + RateBytes <= data.Length)
        {
            XorBlockIntoState(state, data.Slice(offset, RateBytes));
            KeccakF1600(state);
            offset += RateBytes;
        }

        // Absorb the final padded block (pad10*1 with SHA3 domain suffix).
        Span<byte> finalBlock = stackalloc byte[RateBytes];
        finalBlock.Clear();
        data[offset..].CopyTo(finalBlock);
        finalBlock[data.Length - offset] ^= DomainSuffix;
        finalBlock[RateBytes - 1] ^= 0x80;
        XorBlockIntoState(state, finalBlock);
        KeccakF1600(state);

        // Squeeze: SHA3-256 digest fits within a single rate block.
        byte[] digest = new byte[DigestSizeBytes];
        state[..DigestSizeBytes].CopyTo(digest);
        return digest;
    }

    /// <summary>
    /// Streaming SHA3-256 over <paramref name="stream"/> from its current position to EOF. Uses a
    /// bounded buffer so inputs above the in-memory array limit (large mount images) are hashed
    /// without materializing them.
    /// </summary>
    public static byte[] Sha3_256(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (System.Security.Cryptography.SHA3_256.IsSupported)
            return System.Security.Cryptography.SHA3_256.HashData(stream);
        var state = new Sha3StreamState();
        byte[] buffer = new byte[1 << 20];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            state.Append(buffer.AsSpan(0, read));
        return state.Finish();
    }

    /// <summary>Incremental SHA3-256 sponge for streaming inputs. Not thread-safe.</summary>
    public sealed class Sha3StreamState
    {
        private readonly byte[] _state = new byte[StateSizeBytes];
        private readonly byte[] _buffer = new byte[RateBytes];
        private int _buffered;
        private bool _finished;

        /// <summary>Absorbs the next chunk of input.</summary>
        public void Append(ReadOnlySpan<byte> data)
        {
            if (_finished)
                throw new InvalidOperationException("The SHA3 stream state has already been finalized.");

            if (_buffered > 0)
            {
                int take = Math.Min(RateBytes - _buffered, data.Length);
                data[..take].CopyTo(_buffer.AsSpan(_buffered));
                _buffered += take;
                data = data[take..];
                if (_buffered == RateBytes)
                {
                    XorBlockIntoState(_state, _buffer);
                    KeccakF1600(_state);
                    _buffered = 0;
                }
            }

            while (data.Length >= RateBytes)
            {
                XorBlockIntoState(_state, data[..RateBytes]);
                KeccakF1600(_state);
                data = data[RateBytes..];
            }

            if (data.Length > 0)
            {
                data.CopyTo(_buffer);
                _buffered = data.Length;
            }
        }

        /// <summary>Finalizes the sponge with SHA3 padding and returns the 32-byte digest.</summary>
        public byte[] Finish()
        {
            if (_finished)
                throw new InvalidOperationException("The SHA3 stream state has already been finalized.");
            _finished = true;

            Span<byte> finalBlock = stackalloc byte[RateBytes];
            finalBlock.Clear();
            _buffer.AsSpan(0, _buffered).CopyTo(finalBlock);
            finalBlock[_buffered] ^= DomainSuffix;
            finalBlock[RateBytes - 1] ^= 0x80;
            XorBlockIntoState(_state, finalBlock);
            KeccakF1600(_state);

            byte[] digest = new byte[DigestSizeBytes];
            _state.AsSpan(0, DigestSizeBytes).CopyTo(digest);
            return digest;
        }
    }

    private static void XorBlockIntoState(Span<byte> state, ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < block.Length; i++)
            state[i] ^= block[i];
    }

    private static void KeccakF1600(Span<byte> stateBytes)
    {
        // Load state into 25 lanes (little-endian lanes per the Keccak spec).
        Span<ulong> a = stackalloc ulong[25];
        for (int i = 0; i < 25; i++)
            a[i] = BinaryPrimitives.ReadUInt64LittleEndian(stateBytes.Slice(i * 8, 8));

        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> d = stackalloc ulong[5];
        Span<ulong> b = stackalloc ulong[25];

        foreach (ulong rc in RoundConstants)
        {
            // Theta
            for (int x = 0; x < 5; x++)
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++)
                d[x] = c[(x + 4) % 5] ^ RotateLeft(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    a[x + 5 * y] ^= d[x];

            // Rho and Pi (canonical cyclic form from the Keccak reference):
            //   B[y, 2x+3y] = ROT(A[x, y], r[x, y])  ==  B[newX + 5*newY] where
            //   newX = y, newY = (2x + 3y) mod 5.
            b[1] = RotateLeft(a[6], 44);
            b[2] = RotateLeft(a[12], 43);
            b[3] = RotateLeft(a[18], 21);
            b[4] = RotateLeft(a[24], 14);
            b[5] = RotateLeft(a[3], 28);
            b[6] = RotateLeft(a[9], 20);
            b[7] = RotateLeft(a[10], 3);
            b[8] = RotateLeft(a[16], 45);
            b[9] = RotateLeft(a[22], 61);
            b[10] = RotateLeft(a[1], 1);
            b[11] = RotateLeft(a[7], 6);
            b[12] = RotateLeft(a[13], 25);
            b[13] = RotateLeft(a[19], 8);
            b[14] = RotateLeft(a[20], 18);
            b[15] = RotateLeft(a[4], 27);
            b[16] = RotateLeft(a[5], 36);
            b[17] = RotateLeft(a[11], 10);
            b[18] = RotateLeft(a[17], 15);
            b[19] = RotateLeft(a[23], 56);
            b[20] = RotateLeft(a[2], 62);
            b[21] = RotateLeft(a[8], 55);
            b[22] = RotateLeft(a[14], 39);
            b[23] = RotateLeft(a[15], 41);
            b[24] = RotateLeft(a[21], 2);
            b[0] = a[0];

            // Chi
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);

            // Iota
            a[0] ^= rc;
        }

        for (int i = 0; i < 25; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(stateBytes.Slice(i * 8, 8), a[i]);
    }

    private static ulong RotateLeft(ulong value, int offset) =>
        offset == 0 ? value : (value << offset) | (value >> (64 - offset));
}
