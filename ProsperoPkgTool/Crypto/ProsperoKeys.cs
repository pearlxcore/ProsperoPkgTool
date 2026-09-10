using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Clean-room PS5 package key derivation, re-implemented from the reverse-engineering
/// findings (FINDINGS.md §4.1–4.3). All formulas were verified byte-exact against a real
/// Sony-built debug package; no third-party source is used.
/// </summary>
public static class ProsperoKeys
{
    public const int ContentIdPaddedLength = 48;   // content id NUL-padded to 48 bytes
    public const int PasscodeLength = 32;          // ASCII passcode length
    public const int KeySize = 32;                 // all derived keys are 32 bytes

    /// <summary>
    /// ComputeKeys(contentId, passcode, index, useSha3):
    ///   H( H(BE32(index)) || H(contentId.pad48) || passcode_ascii )
    /// where H is SHA3-256 when useSha3, else SHA-256.
    /// </summary>
    public static byte[] ComputeKeys(string contentId, string passcode, uint index, bool useSha3)
    {
        ArgumentNullException.ThrowIfNull(contentId);
        ArgumentNullException.ThrowIfNull(passcode);
        byte[] passcodeBytes = Encoding.ASCII.GetBytes(passcode);
        if (passcodeBytes.Length != PasscodeLength)
            throw new ArgumentException($"Passcode must be exactly {PasscodeLength} ASCII characters.", nameof(passcode));

        byte[] contentIdPadded = new byte[ContentIdPaddedLength];
        Encoding.ASCII.GetBytes(contentId).AsSpan().CopyTo(contentIdPadded);

        Span<byte> indexBe = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(indexBe, index);

        byte[] indexHash = Hash(useSha3, indexBe);
        byte[] contentIdHash = Hash(useSha3, contentIdPadded);

        byte[] data = new byte[96];
        indexHash.CopyTo(data, 0);
        contentIdHash.CopyTo(data, 32);
        passcodeBytes.CopyTo(data, 64);
        return Hash(useSha3, data);
    }

    /// <summary>
    /// EKPFS — the outer PFS image key. EKPFS = ComputeKeys(cid, passcode, 1, sha3).
    /// </summary>
    public static byte[] ComputeEkpfs(string contentId, string passcode) =>
        ComputeKeys(contentId, passcode, 1, useSha3: true);

    /// <summary>
    /// Outer-PFS AES-XTS key ladder (FINDINGS.md §4.3). Given the 16-byte superblock seed:
    ///   inner  = HMAC-SHA256(EKPFS, seed)
    ///   encKey = HMAC-SHA256(inner, LE32(1) || seed)
    ///   tweakKey = encKey[0:16], dataKey = encKey[16:32]
    /// </summary>
    public static (byte[] TweakKey, byte[] DataKey) DeriveOuterPfsXtsKeys(byte[] ekpfs, ReadOnlySpan<byte> seed)
    {
        ArgumentNullException.ThrowIfNull(ekpfs);
        if (ekpfs.Length != KeySize)
            throw new ArgumentException($"EKPFS must be {KeySize} bytes.", nameof(ekpfs));
        if (seed.Length != 16)
            throw new ArgumentException("PFS seed must be 16 bytes.", nameof(seed));

        byte[] inner = HMACSHA256.HashData(ekpfs, seed.ToArray());

        byte[] tweakMessage = new byte[4 + seed.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(tweakMessage, 1);
        seed.CopyTo(tweakMessage.AsSpan(4));
        byte[] encKey = HMACSHA256.HashData(inner, tweakMessage);

        byte[] tweakKey = encKey[..16];
        byte[] dataKey = encKey[16..32];
        return (tweakKey, dataKey);
    }

    private static byte[] Hash(bool useSha3, ReadOnlySpan<byte> data) =>
        useSha3 ? Sha3.Sha3_256(data) : SHA256.HashData(data);
}
