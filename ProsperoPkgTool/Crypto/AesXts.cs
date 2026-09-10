using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// AES-128-XTS block transform used by the PS5 outer PFS image.
///
/// Each PFS block (typically 0x10000 bytes) is a single XTS data unit; the sector index
/// selects the tweak. This is a clean-room implementation of the standard XEX-based
/// tweaked-codebook mode with ciphertext stealing (XTS), ported from the algorithm
/// verified byte-exact against a real package. Ciphertext stealing is not exercised by
/// PFS because every data unit is a whole multiple of the 16-byte AES block.
/// </summary>
public sealed class AesXts : IDisposable
{
    private readonly Aes _dataCipher;   // encrypts/decrypts the data path
    private readonly Aes _tweakCipher;  // encrypts the per-unit tweak

    public AesXts(ReadOnlySpan<byte> dataKey, ReadOnlySpan<byte> tweakKey)
    {
        if (dataKey.Length != 16)
            throw new ArgumentException("XTS data key must be 16 bytes (AES-128).", nameof(dataKey));
        if (tweakKey.Length != 16)
            throw new ArgumentException("XTS tweak key must be 16 bytes (AES-128).", nameof(tweakKey));

        _dataCipher = CreateAes(dataKey);
        _tweakCipher = CreateAes(tweakKey);
    }

    private static Aes CreateAes(ReadOnlySpan<byte> key)
    {
        var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    /// <summary>Decrypt a single XTS data unit identified by its sector index.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ulong sector) => Crypt(ciphertext, sector, encrypt: false);

    /// <summary>Encrypt a single XTS data unit identified by its sector index.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ulong sector) => Crypt(plaintext, sector, encrypt: true);

    private byte[] Crypt(ReadOnlySpan<byte> input, ulong sector, bool encrypt)
    {
        if (input.Length == 0 || input.Length % 16 != 0)
            throw new ArgumentException("XTS data units here must be a non-empty multiple of 16 bytes.", nameof(input));

        // Tweak = E_tweakKey(sector as little-endian u128).
        Span<byte> sectorBytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(sectorBytes, sector);
        // upper 8 bytes remain zero (PFS sector indexes fit in 64 bits)
        byte[] tweak = _tweakCipher.EncryptEcb(sectorBytes.ToArray(), PaddingMode.None);

        byte[] output = new byte[input.Length];
        Span<byte> blockIn = stackalloc byte[16];
        Span<byte> blockOut = stackalloc byte[16];

        for (int i = 0; i < input.Length; i += 16)
        {
            // XOR with the running tweak, transform, XOR again.
            for (int j = 0; j < 16; j++)
                blockIn[j] = (byte)(input[i + j] ^ tweak[j]);

            ReadOnlySpan<byte> src = blockIn;
            byte[] transformed = encrypt
                ? _dataCipher.EncryptEcb(src.ToArray(), PaddingMode.None)
                : _dataCipher.DecryptEcb(src.ToArray(), PaddingMode.None);
            transformed.AsSpan(0, 16).CopyTo(blockOut);

            for (int j = 0; j < 16; j++)
                output[i + j] = (byte)(blockOut[j] ^ tweak[j]);

            MultiplyTweakByX(tweak);
        }
        return output;
    }

    /// <summary>GF(2^128) multiply the tweak by the polynomial x (the XTS "alpha" step).</summary>
    /// <remarks>
    /// The tweak is a little-endian u128 (byte[0] is the least-significant byte, matching the
    /// sector encoding above), so the multiply shifts toward higher byte indices and the
    /// 0x87 reduction lands in byte[0].
    /// </remarks>
    private static void MultiplyTweakByX(byte[] tweak)
    {
        int feedback = 0;
        for (int j = 0; j < 16; j++)
        {
            int nextFeedback = tweak[j] >> 7;
            tweak[j] = (byte)((tweak[j] << 1) | feedback);
            feedback = nextFeedback;
        }
        if (feedback != 0)
            tweak[0] ^= 0x87;
    }

    public void Dispose()
    {
        _dataCipher.Dispose();
        _tweakCipher.Dispose();
    }
}
