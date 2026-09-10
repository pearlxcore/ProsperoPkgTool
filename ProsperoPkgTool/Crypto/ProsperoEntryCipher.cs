using System.Security.Cryptography;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Clean-room implementation of the PS5 CNT protected-entry cipher. Protected entries (the
/// <c>0x80000000</c> flag in <c>Flags1</c>) are stored as an AES-128-CBC transform of the payload
/// zero-padded to a 16-byte boundary, rather than as plaintext.
///
/// The 16-byte key and IV are two halves of a 32-byte seed:
/// <code>
///   keyIndex    = (Flags2 >> 12) &amp; 0xF
///   packageKey  = ComputeKeys(contentId, passcode, keyIndex, publisherProfile)   // 32 bytes
///   seed        = H( metaRow[32] ‖ packageKey )                                  // 32 bytes
///   key         = seed[16..32]
///   iv          = seed[0..16]
///   ciphertext  = AES-128-CBC-NoPad(key, iv, zeroPad(payload, 16))
/// </code>
/// where <c>H</c> is SHA3-256 for the PS5 publisher profile and SHA-256 for the legacy profile.
/// The meta row is the finalized 32-byte entry-table row (id, name offset, flags1, flags2,
/// data offset, data size and 8 reserved zero bytes), so the seed binds the ciphertext to the
/// entry's final layout. This primitive is standalone: the CNT writer and reader do not yet use
/// it (writer parity work in progress).
/// </summary>
public static class ProsperoEntryCipher
{
    /// <summary>Size of a CNT entry-table meta row (bytes).</summary>
    public const int MetaRowSize = 32;

    /// <summary>The derived key/IV seed length (bytes).</summary>
    public const int KeySeedSize = 32;

    /// <summary>Zero-padded stored length of an entry payload, rounded up to the AES block size.</summary>
    public static int PaddedLength(int dataSize) => checked((dataSize + 15) & ~15);

    /// <summary>
    /// Derives the 32-byte key/IV seed from the finalized meta row and the package key for
    /// <paramref name="keyIndex"/>. <paramref name="publisherProfile"/> selects SHA3-256 (PS5) or
    /// SHA-256 (legacy) for both the package-key and seed hashes.
    /// </summary>
    public static byte[] DeriveKeySeed(
        ReadOnlySpan<byte> metaRow, string contentId, string passcode, uint keyIndex, bool publisherProfile)
    {
        if (metaRow.Length != MetaRowSize)
            throw new ArgumentException($"Meta row must be {MetaRowSize} bytes.", nameof(metaRow));

        byte[] packageKey = ProsperoKeys.ComputeKeys(contentId, passcode, keyIndex, publisherProfile);
        byte[] data = new byte[MetaRowSize + KeySeedSize];
        metaRow.CopyTo(data);
        packageKey.CopyTo(data, MetaRowSize);
        return publisherProfile ? Sha3.Sha3_256(data) : SHA256.HashData(data);
    }

    /// <summary>Splits a key/IV seed into its (key, iv) halves: key = seed[16..32], iv = seed[0..16].</summary>
    public static (byte[] Key, byte[] Iv) DeriveKeyIv(ReadOnlySpan<byte> keySeed)
    {
        if (keySeed.Length != KeySeedSize)
            throw new ArgumentException($"Key seed must be {KeySeedSize} bytes.", nameof(keySeed));

        return (keySeed[16..32].ToArray(), keySeed[..16].ToArray());
    }

    /// <summary>
    /// Encrypts the payload into its stored form: zero-pad to 16 bytes, then AES-128-CBC with no
    /// padding. The returned ciphertext length is <see cref="PaddedLength(int)"/>.
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> keySeed)
    {
        int stored = PaddedLength(payload.Length);
        byte[] buffer = new byte[stored];
        payload.CopyTo(buffer);
        (byte[] key, byte[] iv) = DeriveKeyIv(keySeed);
        return Transform(buffer, key, iv, encrypt: true);
    }

    /// <summary>Encrypts a payload using a key/IV seed derived from the finalized meta row.</summary>
    public static byte[] Encrypt(
        ReadOnlySpan<byte> payload, ReadOnlySpan<byte> metaRow,
        string contentId, string passcode, uint keyIndex, bool publisherProfile)
    {
        byte[] seed = DeriveKeySeed(metaRow, contentId, passcode, keyIndex, publisherProfile);
        return Encrypt(payload, seed);
    }

    /// <summary>
    /// Decrypts a stored (16-byte-aligned) entry body back to its zero-padded plaintext. The caller
    /// truncates to the entry's declared <c>DataSize</c>. Corrupt or truncated input throws.
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> keySeed)
    {
        if (ciphertext.Length == 0 || (ciphertext.Length & 15) != 0)
            throw new ArgumentException("Ciphertext length must be a non-zero multiple of 16.", nameof(ciphertext));

        (byte[] key, byte[] iv) = DeriveKeyIv(keySeed);
        return Transform(ciphertext.ToArray(), key, iv, encrypt: false);
    }

    /// <summary>Decrypts a stored entry body using a key/IV seed derived from the finalized meta row.</summary>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> metaRow,
        string contentId, string passcode, uint keyIndex, bool publisherProfile)
    {
        byte[] seed = DeriveKeySeed(metaRow, contentId, passcode, keyIndex, publisherProfile);
        return Decrypt(ciphertext, seed);
    }

    private static byte[] Transform(byte[] buffer, byte[] key, byte[] iv, bool encrypt)
    {
        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.KeySize = 128;
        aes.Key = key;
        aes.IV = iv;
        using ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return transform.TransformFinalBlock(buffer, 0, buffer.Length);
    }
}
