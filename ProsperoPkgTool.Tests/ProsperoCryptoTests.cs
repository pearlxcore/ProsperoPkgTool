using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;
using Xunit;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Byte-exact validation of the clean-room crypto/container primitives against values
/// verified from a real Sony-built debug package (content id
/// IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX, passcode 12345678923456789102123901202333).
/// Every constant here was independently reproduced by the reverse-engineering prototypes
/// (FINDINGS.md §4); these tests lock the clean-room implementation to that ground truth.
/// </summary>
public class ProsperoCryptoTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    // ---- SHA3-256 self-consistency (NIST-known vectors) ------------------------------

    [Fact]
    public void Sha3_256_EmptyInput_MatchesNistVector()
    {
        // NIST SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        Assert.Equal(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            Convert.ToHexString(Sha3.Sha3_256(ReadOnlySpan<byte>.Empty)).ToLowerInvariant());
    }

    [Fact]
    public void Sha3_256_Abc_MatchesNistVector()
    {
        // NIST SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
        Assert.Equal(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            Convert.ToHexString(Sha3.Sha3_256("abc"u8.ToArray())).ToLowerInvariant());
    }

    // ---- Key derivation (FINDINGS.md §4.1–4.3) ---------------------------------------

    [Fact]
    public void Ekpfs_MatchesVerifiedValue()
    {
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        Assert.Equal(
            "46a3ee1f2ad55b603b7188ba3943828a7559b4418aeddb06ecbfe85bbb26c73d",
            Convert.ToHexString(ekpfs).ToLowerInvariant());
    }

    [Fact]
    public void OuterPfsXtsKeys_MatchVerifiedValues()
    {
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        byte[] seed = Convert.FromHexString("566fd27fd048a11ebf72255a5c9d5e63");
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, seed);
        Assert.Equal("c62f5703d401db5d3a6351b06a48297e", Convert.ToHexString(tweakKey).ToLowerInvariant());
        Assert.Equal("ce07785b346590ee60dd8ed96f79ad57", Convert.ToHexString(dataKey).ToLowerInvariant());
    }

    // ---- Keystone (FINDINGS.md §4.6) ---------------------------------------------------

    [Fact]
    public void Keystone_ValidatesAgainstRealKeystone()
    {
        byte[] keystone = File.ReadAllBytes(Fixture("test.keystone"));
        Assert.Equal(Keystone.Size, keystone.Length);
        Assert.Equal(3, Keystone.GetVersion(keystone));
        Assert.True(Keystone.Validate(keystone, Passcode), "Real keystone should validate with its passcode.");
        Assert.False(Keystone.Validate(keystone, "00000000000000000000000000000000"),
            "Real keystone must not validate under the wrong passcode.");
    }

    // ---- Outer PFS decrypt (FINDINGS.md §3.3, §4.4, §4.5) ----------------------------

    [Fact]
    public void OuterPfs_SuperblockAndIcv_AreValid()
    {
        using var stream = File.OpenRead(Fixture("test.pkg"));
        // FIH: PFS offset 0x10, PFS size 0x18 (little-endian).
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        var pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        Assert.Equal(5, pfs.SuperblockIndex);          // verified: superblock at block 5 of 10
        Assert.Equal("566fd27fd048a11ebf72255a5c9d5e63", Convert.ToHexString(pfs.Seed).ToLowerInvariant());
        Assert.True(pfs.VerifySuperblockIcv(), "Superblock ICV must verify.");
    }

    [Fact]
    public void OuterPfs_DecryptsInnerImageToKeystoneAndElf()
    {
        using var stream = File.OpenRead(Fixture("test.pkg"));
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        var pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        byte[] innerImage = pfs.ReadInnerImage(xts);
        Assert.Equal((pfs.SuperblockIndex - 1) * (int)OuterPfsReader.BlockSize, innerImage.Length);

        // The decrypted inner image must contain recognizable plaintext somewhere:
        // the keystone magic and/or an ELF header (the inner image packs them).
        bool hasKeystone = ContainsSequence(innerImage, "keystone"u8.ToArray());
        bool hasElf = ContainsSequence(innerImage, [0x7F, (byte)'E', (byte)'L', (byte)'F']);
        Assert.True(hasKeystone || hasElf,
            "Decrypted inner image should contain keystone or ELF plaintext (XTS keys are correct).");
    }

    // ---- deterministic CNT+0x1000 header wrap (scene method) -------------------------

    [Fact]
    public void BuildCntHeaderWrap_SyntheticHeader_MatchesReferenceVector()
    {
        // Golden vector produced by the reference publisher RSA path (LibProsperoPkg
        // ProsperoPublisherRsa.BuildCntHeaderWrap) for header[i] = i*31 + 7. It locks the
        // deterministic PKCS#1 v1.5 padding stream (SHA-256-seeded MT19937) byte-for-byte.
        byte[] header = new byte[ProsperoRsaKeys.CntHeaderSize];
        for (int i = 0; i < header.Length; i++)
            header[i] = (byte)(i * 31 + 7);

        const string expected =
            "514d7e94f6d2f1c331d3ef61be22caa1d9a0d243976cbb573ccdd7d6f972cad1" +
            "8418c22b4f6f3e81b68569557512e712878b547ce3fda45534b01ac2fb878d97" +
            "9004452b14f8d2add6ddb02fd42e255ea6f73ed05b7af0c3da6917ca17fee6b8" +
            "41d0aa376f16f90507b83850e9dc548702c97ddb53bce33e32562a4dc8aa7a70" +
            "9c8df02a226cd71ad1ece1264b12d6c64acde93cac7500ca18dc3f12d8559b6e" +
            "04fd390b57953e730c66c431b436d81c5c80f73854daf4b3062e74011015ce15e" +
            "b089bf6369a976365bc6246bf7398494a6e7eda74da58812b9e656ac9db03d4ce" +
            "6b7fda02059922d787dd74223f81bf6d2d89373a7f70da02d939a68ecd052b7e1" +
            "eb394e901893b62c69dcc8d7f9c3568f34233100424340efd5c597338ea01f66d" +
            "d95bbcaa2589b0433d05c65c5367a7fd78485967ff2dffc88b95ce519122e649a" +
            "4519921ec4dabd7e400323af7878d04efd2c6eeab543115c55b60951f5cd9018e" +
            "48c48dde2f2f425901279d9d69127b14a48043eec029cfae0ff6a97c80";

        string actual = Convert.ToHexString(ProsperoRsaKeys.BuildCntHeaderWrap(header)).ToLowerInvariant();
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void BuildCntHeaderWrap_IsDeterministic_AndVerifies()
    {
        byte[] header = new byte[ProsperoRsaKeys.CntHeaderSize];
        for (int i = 0; i < header.Length; i++)
            header[i] = (byte)(i * 7 + 3);
        // A finalized CNT always stamps the FIH-relative pfs-image offset (0x10000) at +0x410.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(header.AsSpan(0x410, 8), 0x10000);

        byte[] first = ProsperoRsaKeys.BuildCntHeaderWrap(header);
        byte[] second = ProsperoRsaKeys.BuildCntHeaderWrap(header);
        Assert.Equal(first, second);
        Assert.Equal(ProsperoRsaKeys.HeaderSignatureSize, first.Length);
        Assert.True(ProsperoRsaKeys.VerifyCntHeaderWrap(header, first));
        Assert.False(ProsperoRsaKeys.VerifyCntHeaderWrap(header, new byte[ProsperoRsaKeys.HeaderSignatureSize]));
    }

    // ---- CNT protected-entry cipher (isolated primitive) -----------------------------

    private static byte[] MetaRow(uint flags1, uint flags2, uint dataSize)
    {
        byte[] row = new byte[ProsperoEntryCipher.MetaRowSize];
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x00), 0x0402);
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x04), 0);
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x08), flags1);
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x0C), flags2);
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x10), 0x2000);
        BinaryPrimitives.WriteUInt32BigEndian(row.AsSpan(0x14), dataSize);
        return row;
    }

    [Fact]
    public void EntryCipher_PaddedLength_RoundsUpToBlockBoundary()
    {
        Assert.Equal(0, ProsperoEntryCipher.PaddedLength(0));
        Assert.Equal(16, ProsperoEntryCipher.PaddedLength(1));
        Assert.Equal(16, ProsperoEntryCipher.PaddedLength(16));
        Assert.Equal(32, ProsperoEntryCipher.PaddedLength(17));
    }

    [Fact]
    public void EntryCipher_KeyAndIv_AreSeedHalves()
    {
        byte[] seed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        (byte[] key, byte[] iv) = ProsperoEntryCipher.DeriveKeyIv(seed);
        Assert.Equal(seed[16..32], key);
        Assert.Equal(seed[..16], iv);
    }

    [Fact]
    public void EntryCipher_EncryptThenDecrypt_RoundTrips()
    {
        byte[] row = MetaRow(0x80000000, 3 << 12, 0x11);
        byte[] payload = new byte[0x11];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i * 5 + 1);

        byte[] cipher = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: true);
        Assert.Equal(ProsperoEntryCipher.PaddedLength(payload.Length), cipher.Length);
        Assert.False(cipher.AsSpan(0, payload.Length).SequenceEqual(payload), "Ciphertext must not equal plaintext.");

        byte[] round = ProsperoEntryCipher.Decrypt(cipher, row, ContentId, Passcode, 3, publisherProfile: true);
        Assert.Equal(payload, round[..payload.Length]);
        Assert.All(round[payload.Length..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void EntryCipher_Encrypt_IsDeterministic()
    {
        byte[] row = MetaRow(0x80000000, 3 << 12, 0x20);
        byte[] payload = new byte[0x20];
        byte[] first = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: true);
        byte[] second = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: true);
        Assert.Equal(first, second);
    }

    [Fact]
    public void EntryCipher_CiphertextDependsOnKeyIndexAndMetaRow()
    {
        byte[] payload = new byte[0x10];
        byte[] row = MetaRow(0x80000000, 3 << 12, 0x10);
        byte[] key3 = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: true);
        byte[] key4 = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 4, publisherProfile: true);
        byte[] otherRow = MetaRow(0x80000000, 3 << 12, 0x20);
        byte[] rowVariant = ProsperoEntryCipher.Encrypt(payload, otherRow, ContentId, Passcode, 3, publisherProfile: true);
        Assert.NotEqual(key3, key4);
        Assert.NotEqual(key3, rowVariant);
    }

    [Fact]
    public void EntryCipher_PublisherAndLegacyProfilesDiffer()
    {
        byte[] row = MetaRow(0x80000000, 3 << 12, 0x10);
        byte[] payload = new byte[0x20];
        byte[] publisher = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: true);
        byte[] legacy = ProsperoEntryCipher.Encrypt(payload, row, ContentId, Passcode, 3, publisherProfile: false);
        Assert.NotEqual(publisher, legacy);
    }

    [Fact]
    public void EntryCipher_Decrypt_RejectsMisalignedOrEmptyInput()
    {
        byte[] seed = ProsperoEntryCipher.DeriveKeySeed(
            MetaRow(0x80000000, 3 << 12, 0x10), ContentId, Passcode, 3, publisherProfile: true);
        Assert.Throws<ArgumentException>(() => ProsperoEntryCipher.Decrypt(new byte[15], seed));
        Assert.Throws<ArgumentException>(() => ProsperoEntryCipher.Decrypt([], seed));
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                return true;
        }
        return false;
    }
}
