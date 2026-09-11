using System.Buffers.Binary;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// The published PS5 RSA-3072 public moduli the CNT container uses for key wrapping and the
/// metadata header signature. These are public constants shipped with the Prospero publishing
/// tools — they are not secret retail keys. Each modulus is 384 bytes (big-endian).
///
/// <c>PasscodeModuli</c> — the seven 384-byte moduli in <c>Keys/Data/passcode.bin</c>; each wraps
/// one of the seven passcode-derived package keys (index 0..6) under RSA-PKCS#1 v1.5. Index 0 wraps
/// the raw passcode ASCII; indices 1..6 wrap the SHA3-derived keys.
/// <c>MountImageModulus</c> — the 384-byte modulus in <c>Keys/Data/mount_image.bin</c>; wraps the
/// 32-byte EKPFS (the image key) under RSA-PKCS#1 v1.5 (5 whole wraps + a truncated 6th = 0x800 bytes).
/// <c>MetadataModulus</c> — the 384-byte public modulus of the PKG-metadata RSA-3072 key, recovered
/// from the published private key; the CNT header signature (+0x1000) is an RSA-PKCS#1 v1.5
/// encryption of the 32-byte SHA3-256 header digest under this modulus.
/// </summary>
public static class ProsperoRsaKeys
{
    public const int ModulusSize = 384;
    public const int PasscodeModulusCount = 7;
    public const int ImageKeyEntrySize = 0x800; // 2048 bytes: 5 full 384-byte wraps + 128-byte truncation
    public const int HeaderSignatureSize = 384;
    public const int EntryKeysSize = 32 + 7 * 32 + 7 * ModulusSize; // seed + 7 digests + 7 wrapped keys = 2944
    /// <summary>Width of the CNT region the header wrap covers (bytes).</summary>
    public const int CntHeaderSize = 4096;
    /// <summary>Passcode-bank index whose public modulus wraps the CNT header digest.</summary>
    public const int CntWrapPasscodeIndex = 3;

    private static readonly byte[] s_passcodeBlob = LoadResource("ProsperoPkgTool.Keys.passcode.bin");
    private static readonly byte[] s_mountImageBlob = LoadResource("ProsperoPkgTool.Keys.mount_image.bin");
    private static readonly byte[] s_metadataModulus = LoadResource("ProsperoPkgTool.Keys.metadata_modulus.bin");

    /// <summary>True when every modulus blob was loaded from embedded resources.</summary>
    public static bool IsAvailable =>
        s_passcodeBlob.Length == PasscodeModulusCount * ModulusSize
        && s_mountImageBlob.Length == ModulusSize
        && s_metadataModulus.Length == ModulusSize;

    /// <summary>The seven passcode-key moduli (big-endian, 384 bytes each).</summary>
    public static ReadOnlySpan<byte> PasscodeBlob => s_passcodeBlob;

    /// <summary>The mount-image modulus (384 bytes, big-endian).</summary>
    public static ReadOnlySpan<byte> MountImageModulus => s_mountImageBlob;

    /// <summary>The PKG-metadata public modulus (384 bytes, big-endian).</summary>
    public static ReadOnlySpan<byte> MetadataModulus => s_metadataModulus;

    /// <summary>Returns passcode modulus <paramref name="index"/> (0..6).</summary>
    public static ReadOnlySpan<byte> GetPasscodeModulus(int index)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(index, 0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, PasscodeModulusCount);
        return s_passcodeBlob.AsSpan(index * ModulusSize, ModulusSize);
    }

    /// <summary>
    /// RSA-PKCS#1 v1.5 encrypts <paramref name="data"/> under the big-endian
    /// <paramref name="modulus"/> (public exponent 65537). Returns a ciphertext the length of the
    /// modulus (384 bytes for RSA-3072). Each call uses fresh random padding, so the output is not
    /// byte-reproducible.
    /// </summary>
    public static byte[] RsaPkcs1Encrypt(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> data)
    {
        if (modulus.Length != ModulusSize)
            throw new ArgumentException($"Modulus must be {ModulusSize} bytes.", nameof(modulus));

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = modulus.ToArray(),
            Exponent = [0x01, 0x00, 0x01],
        });
        return rsa.Encrypt(data.ToArray(), RSAEncryptionPadding.Pkcs1);
    }

    /// <summary>
    /// Builds the 0x800-byte CNT IMAGE_KEY entry (id 0x0020): back-to-back RSA-PKCS#1 wraps of the
    /// 32-byte EKPFS under the mount-image modulus. 5 whole 384-byte wraps + the first 128 bytes of
    /// a 6th wrap (= 2048 bytes total). When <paramref name="deterministic"/> is set the wraps use
    /// <see cref="RsaPkcs1EncryptDeterministic"/>, making the entry (and the package) reproducible.
    /// </summary>
    public static byte[] BuildImageKeyEntry(ReadOnlySpan<byte> ekpfs, bool deterministic = false)
    {
        if (ekpfs.Length != 32)
            throw new ArgumentException("EKPFS must be 32 bytes.", nameof(ekpfs));

        var entry = new byte[ImageKeyEntrySize];
        int off = 0;
        while (off < ImageKeyEntrySize)
        {
            byte[] wrap = deterministic
                ? RsaPkcs1EncryptDeterministic(MountImageModulus, ekpfs)
                : RsaPkcs1Encrypt(MountImageModulus, ekpfs);
            int take = Math.Min(ModulusSize, ImageKeyEntrySize - off);
            wrap.AsSpan(0, take).CopyTo(entry.AsSpan(off));
            off += take;
        }
        return entry;
    }

    /// <summary>
    /// Builds the CNT ENTRY_KEYS entry (id 0x0010, 2944 bytes): a 32-byte seed digest (SHA3-256 of
    /// the content id padded to 48 bytes), seven 32-byte per-key digests, then seven 384-byte
    /// RSA-wrapped passcode keys. Index 0 wraps the raw passcode ASCII; indices 1..6 wrap the
    /// SHA3-derived package keys. When <paramref name="deterministic"/> is set the wraps use
    /// <see cref="RsaPkcs1EncryptDeterministic"/>, making the entry (and the package) reproducible.
    /// </summary>
    public static byte[] BuildEntryKeysEntry(string contentId, string passcode, bool deterministic = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(passcode);

        var entry = new byte[EntryKeysSize];
        int off = 0;

        // Seed digest = SHA3-256(content_id padded to 48 bytes).
        Span<byte> cid = stackalloc byte[48];
        cid.Clear();
        Encoding.ASCII.GetBytes(contentId, cid);
        Sha3.Sha3_256(cid).CopyTo(entry.AsSpan(off));
        off += 32;

        // Per-key digests (7 × 32): SHA3-256(key) XOR key for each passcode-derived key.
        // Index 0's key is the raw passcode ASCII (32 bytes).
        for (int i = 0; i < PasscodeModulusCount; i++)
        {
            byte[] key = i == 0
                ? Encoding.ASCII.GetBytes(passcode)
                : ProsperoKeys.ComputeKeys(contentId, passcode, (uint)i, useSha3: true);

            byte[] digest = Sha3.Sha3_256(key);
            for (int j = 0; j < 32; j++)
                digest[j] ^= key[j];
            digest.CopyTo(entry.AsSpan(off));
            off += 32;
        }

        // Wrapped keys (7 × 384): RSA-PKCS#1 wrap each key under the matching modulus.
        for (int i = 0; i < PasscodeModulusCount; i++)
        {
            byte[] key = i == 0
                ? Encoding.ASCII.GetBytes(passcode)
                : ProsperoKeys.ComputeKeys(contentId, passcode, (uint)i, useSha3: true);

            byte[] wrap = deterministic
                ? RsaPkcs1EncryptDeterministic(GetPasscodeModulus(i), key)
                : RsaPkcs1Encrypt(GetPasscodeModulus(i), key);
            wrap.CopyTo(entry.AsSpan(off));
            off += ModulusSize;
        }

        return entry;
    }

    /// <summary>
    /// Builds the deterministic CNT+0x1000 wrap exactly as the publishing tools do: SHA3-256 of the
    /// first <see cref="CntHeaderSize"/> CNT bytes, then deterministic RSA-PKCS#1 v1.5 wrapping
    /// under passcode modulus <see cref="CntWrapPasscodeIndex"/> with exponent 65537. The verifier
    /// reproduces this public operation and compares bytes, so the padding must be deterministic.
    /// The caller passes the finalized header (its CNT+0x410 pfs-image-offset field already holds
    /// the FIH-relative 0x10000); this method hashes the bytes verbatim.
    /// </summary>
    public static byte[] BuildCntHeaderWrap(ReadOnlySpan<byte> cntHeader)
    {
        if (cntHeader.Length < CntHeaderSize)
            throw new ArgumentException($"The CNT header wrap requires at least 0x{CntHeaderSize:X} bytes.", nameof(cntHeader));

        byte[] digest = Sha3.Sha3_256(cntHeader[..CntHeaderSize]);
        return RsaPkcs1EncryptDeterministic(GetPasscodeModulus(CntWrapPasscodeIndex), digest);
    }

    /// <summary>
    /// Reproduces and compares the deterministic CNT+0x1000 header wrap. As the reference verifier
    /// does, the FIH-relative pfs-image-offset field (CNT+0x410) is normalised to 0x10000 before
    /// hashing, so a legacy header stamped with 0 still verifies.
    /// </summary>
    public static bool VerifyCntHeaderWrap(ReadOnlySpan<byte> cntHeader, ReadOnlySpan<byte> storedWrap)
    {
        if (storedWrap.Length != HeaderSignatureSize || cntHeader.Length < CntHeaderSize)
            return false;

        byte[] header = cntHeader[..CntHeaderSize].ToArray();
        ulong pfsImageOffset = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(0x410, 8));
        if (pfsImageOffset != 0 && pfsImageOffset != 0x10000)
            BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(0x410, 8), 0x10000);

        return CryptographicOperations.FixedTimeEquals(BuildCntHeaderWrap(header), storedWrap);
    }

    /// <summary>
    /// Deterministic RSASSA/EME-PKCS#1 v1.5 public-key wrap (exponent 65537). The non-zero padding
    /// bytes come from an MT19937 stream seeded by <c>SHA-256(SHA-256(modulus || data))</c>, so a
    /// given <paramref name="modulus"/>/<paramref name="data"/> pair always yields the same
    /// ciphertext. Used for the re-encryptable CNT header wrap.
    /// </summary>
    public static byte[] RsaPkcs1EncryptDeterministic(ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> data)
    {
        if (modulus.Length != ModulusSize)
            throw new ArgumentException($"Modulus must be {ModulusSize} bytes.", nameof(modulus));
        if (data.Length > modulus.Length - 11)
            throw new ArgumentException("RSA PKCS#1 v1.5 input is too large for the modulus.", nameof(data));

        var block = new byte[modulus.Length];
        block[1] = 0x02;
        int padLength = block.Length - data.Length - 3;

        byte[] seedSource = new byte[modulus.Length + data.Length];
        modulus.CopyTo(seedSource);
        data.CopyTo(seedSource.AsSpan(modulus.Length));
        byte[] seedHash = SHA256.HashData(SHA256.HashData(seedSource));

        uint[] seedWords = new uint[seedHash.Length / 4];
        for (int i = 0; i < seedWords.Length; i++)
        {
            int o = i * 4;
            seedWords[i] = (uint)((seedHash[o] << 24) | (seedHash[o + 1] << 16) | (seedHash[o + 2] << 8) | seedHash[o + 3]);
        }

        var rng = new MersenneTwister(seedWords);
        int pos = 2;
        int padEnd = 2 + padLength;
        while (pos < padEnd)
        {
            var words = new byte[48];
            for (int j = 0; j < 12; j++)
            {
                uint value = rng.NextUInt32();
                int o = j * 4;
                words[o] = (byte)(value >> 24);
                words[o + 1] = (byte)(value >> 16);
                words[o + 2] = (byte)(value >> 8);
                words[o + 3] = (byte)value;
            }
            foreach (byte b in SHA256.HashData(words))
            {
                if (b == 0)
                    continue;
                block[pos++] = b;
                if (pos == padEnd)
                    break;
            }
        }

        block[padEnd] = 0x00;
        data.CopyTo(block.AsSpan(padEnd + 1));
        return RsaPublicModExp(block, modulus, 65537);
    }

    private static byte[] RsaPublicModExp(byte[] value, ReadOnlySpan<byte> modulusBytes, int exponent)
    {
        BigInteger valueInt = new(value, isUnsigned: true, isBigEndian: true);
        BigInteger modulus = new(modulusBytes, isUnsigned: true, isBigEndian: true);
        byte[] result = BigInteger.ModPow(valueInt, exponent, modulus).ToByteArray(isUnsigned: true, isBigEndian: true);
        if (result.Length > modulusBytes.Length)
            throw new CryptographicException("RSA result exceeds the modulus size.");

        var padded = new byte[modulusBytes.Length];
        result.CopyTo(padded, padded.Length - result.Length);
        return padded;
    }

    private static byte[] LoadResource(string name)
    {
        Assembly asm = typeof(ProsperoRsaKeys).Assembly;
        using Stream? s = asm.GetManifestResourceStream(name);
        if (s is null)
            return [];
        using var ms = new MemoryStream(checked((int)s.Length));
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
