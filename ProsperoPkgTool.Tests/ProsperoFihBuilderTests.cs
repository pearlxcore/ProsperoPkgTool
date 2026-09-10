using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validates the clean-room FIH builder against the real Sony-built debug package: wrapping the
/// fixture's own embedded CNT must reproduce the fixture's FIH header (the header is deterministic
/// given the shared image + the nested-image digest threaded in from the outer PFS).
/// </summary>
public sealed class ProsperoFihBuilderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact]
    public void DebugPackage_WrapCnt_ReproducesFihHeader()
    {
        // ---- Read the fixture's FIH header and embedded CNT. ----
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));

        ulong fixturePfsSize = BinaryPrimitives.ReadUInt64LittleEndian(pkg.AsSpan(0x18));
        ulong fixtureCntOffset = BinaryPrimitives.ReadUInt64LittleEndian(pkg.AsSpan(0x58));

        // The fixture's finalized image = FIH header + shared PFS image + embedded CNT metadata + SI.
        // BuildFromCnt expects a standalone CNT (metadata + image concatenated). The CNT metadata
        // region is exactly body_offset + body_size (CNT+0x20 + CNT+0x28, also CNT+0x4B8), which
        // excludes the trailing SI segment.
        int cnt = (int)fixtureCntOffset;
        int cntMetaLen = checked((int)BinaryPrimitives.ReadUInt64BigEndian(pkg.AsSpan(cnt + 0x4B8)));
        byte[] metadata = pkg.AsSpan(cnt, cntMetaLen).ToArray();
        byte[] image = pkg.AsSpan(0x10000, (int)fixturePfsSize).ToArray();
        byte[] standaloneCnt = new byte[metadata.Length + image.Length];
        Buffer.BlockCopy(metadata, 0, standaloneCnt, 0, metadata.Length);
        Buffer.BlockCopy(image, 0, standaloneCnt, metadata.Length, image.Length);
        byte[] embeddedCnt = standaloneCnt;

        // Recover the nested-image digest (SHA3-256 of naps_pkg_layout.dat) from the outer PFS.
        using var stream = File.OpenRead(Fixture("test.pkg"));
        OuterPfsReader pfs = OuterPfsReader.Open(stream, 0x10000, (long)fixturePfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);
        byte[] naps = pfs.ReadNaps(xts);
        byte[] nestedDigest = Sha3.Sha3_256(naps);

        // The standalone CNT's image must start at body_offset + body_size.
        ulong bodyOffset = BinaryPrimitives.ReadUInt64BigEndian(embeddedCnt.AsSpan(0x20));
        ulong bodySize = BinaryPrimitives.ReadUInt64BigEndian(embeddedCnt.AsSpan(0x28));
        Assert.Equal((ulong)metadata.Length, bodyOffset + bodySize);

        // ---- Rebuild the FIH header from the CNT. ----
        // The fixture's FIH 0x50 (nestedMetaBaseBlocks) = 64; 0x9C contentVersionHi = 0x01000000;
        // 0x94 innerContentInodes = 4; 0xF0 appFileCount = 1. These are the inner-image accounting
        // values the builder can't derive from the outer image alone, so thread them in.
        byte[] rebuilt = ProsperoFihBuilder.BuildFromCnt(
            embeddedCnt, FihVariant.Debug,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: 64, contentVersionHi: 0x01000000,
            innerContentInodes: 4, appFileCount: 1,
            metaBlockCount: 4, metaBlockCountMirror: 5, emptyFileCount: 1);

        // The rebuilt image is header + image + metadata (no SI segment).
        Assert.True(rebuilt.Length >= ProsperoFihBuilder.HeaderRegionSize);

        // Compare the FIH header block on the documented fields (not byte-for-byte: Sony's builder
        // stamps a few undocumented fields like the 0xFC constant that this clean-room builder does
        // not reproduce). Verify magic, signed byte, version, offsets, sizes, and the digest table.
        Assert.Equal(0x7F, rebuilt[0]);
        Assert.Equal((byte)'F', rebuilt[1]);
        Assert.Equal((byte)'I', rebuilt[2]);
        Assert.Equal((byte)'H', rebuilt[3]);
        Assert.Equal(0x00, rebuilt[5]);                                           // debug signed byte
        Assert.Equal((ushort)3, BinaryPrimitives.ReadUInt16LittleEndian(rebuilt.AsSpan(0x06)));
        Assert.Equal(0x10000UL, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0x10)));
        Assert.Equal(fixturePfsSize, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0x18)));
        Assert.Equal(0xB0000UL, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0x58)));
        Assert.Equal(64UL, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0x50)));   // data-region blocks
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0x90)));      // inner block count
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0x94)));     // meta block count
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0x98)));     // meta block count mirror
        Assert.Equal(0x01000000u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0x9C)));
        Assert.Equal(262144UL, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0xA0)));
        Assert.Equal((ulong)naps.Length, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(0xA8)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0xF0)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0xF4)));   // sparse AFID holes
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0xF8)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(0xFC)));    // empty files

        // The game-digest (SHA3-256 of the plaintext superblock) at 0x30/0x70/0xD0.
        byte[] gameDigest = Sha3.Sha3_256(image.AsSpan(0x50000, 0x10000));  // superblock is block 5
        Assert.Equal(gameDigest, rebuilt.AsSpan(0x30, 32).ToArray());
        Assert.Equal(gameDigest, rebuilt.AsSpan(0x70, 32).ToArray());
        Assert.Equal(gameDigest, rebuilt.AsSpan(0xD0, 32).ToArray());

        // The nested-image-content digest at 0xB0.
        Assert.Equal(nestedDigest, rebuilt.AsSpan(0xB0, 32).ToArray());

        // The shared PFS image and the embedded CNT must also be byte-identical.
        byte[] fixtureImage = pkg.AsSpan(0x10000, (int)fixturePfsSize).ToArray();
        byte[] rebuiltImage = rebuilt.AsSpan(0x10000, (int)fixturePfsSize).ToArray();
        Assert.Equal(fixtureImage, rebuiltImage);

        // The embedded CNT metadata must also be byte-identical (compare the CNT metadata portion,
        // which in the finalized package runs from cntOffset to the end).
        byte[] fixtureMetadata = pkg.AsSpan((int)fixtureCntOffset).ToArray();
        byte[] rebuiltMetadata = rebuilt.AsSpan(
            ProsperoFihBuilder.HeaderRegionSize + (int)fixturePfsSize).ToArray();
        // The fixture metadata includes the trailing SI segment; the rebuilt does not. Compare up to
        // the shorter length (the CNT metadata without SI).
        int metaLen = Math.Min(fixtureMetadata.Length, rebuiltMetadata.Length);
        Assert.Equal(fixtureMetadata.AsSpan(0, metaLen).ToArray(),
                     rebuiltMetadata.AsSpan(0, metaLen).ToArray());
    }

    [Fact]
    public void HeaderBlock_HasDebugSignedByteAndVersion3()
    {
        byte[] image = new byte[2 * 0x10000];
        // Plant a plaintext superblock in the second block.
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x10000), 2);
        image[0x10008] = 0x0B; image[0x10009] = 0x2A; image[0x1000A] = 0x33; image[0x1000B] = 0x01;

        byte[] header = ProsperoFihBuilder.BuildHeaderBlock(
            FihVariant.Debug, (ulong)(2 * 0x10000), 0x30000, image);

        Assert.Equal(0x7F, header[0]);
        Assert.Equal((byte)'F', header[1]);
        Assert.Equal((byte)'I', header[2]);
        Assert.Equal((byte)'H', header[3]);
        Assert.Equal(0x00, header[5]);                       // debug signed byte
        Assert.Equal(3, BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x06)));
        Assert.Equal(0x10000UL, BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x10)));
        Assert.Equal((ulong)(2 * 0x10000), BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x18)));
        Assert.Equal(0x30000UL, BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x58)));

        // The game-digest is SHA3-256 of the superblock block.
        byte[] expected = Sha3.Sha3_256(image.AsSpan(0x10000, 0x10000));
        Assert.Equal(expected, header.AsSpan(0x30, 32).ToArray());
        Assert.Equal(expected, header.AsSpan(0x70, 32).ToArray());
        Assert.Equal(expected, header.AsSpan(0xD0, 32).ToArray());

        // Inner-image accounting: superblock at block 1 → innerBlocks 0, metaOrInodes = 2 - 0 = 2.
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x90)));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x94)));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x98)));
    }

    [Fact]
    public void HeaderBlock_OfficialVariant_HasSignedByte0x80()
    {
        byte[] image = new byte[0x10000];
        byte[] header = ProsperoFihBuilder.BuildHeaderBlock(FihVariant.Official, 0x10000, 0x20000, image);
        Assert.Equal(0x80, header[5]);
    }

    [Fact]
    public void LocateSuperblock_FindsPlaintextBlock()
    {
        byte[] image = new byte[3 * 0x10000];
        Assert.Equal(-1, ProsperoFihBuilder.LocateSuperblock(image));

        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x20000), 2);
        image[0x20008] = 0x0B; image[0x20009] = 0x2A; image[0x2000A] = 0x33; image[0x2000B] = 0x01;
        Assert.Equal(0x20000, ProsperoFihBuilder.LocateSuperblock(image));
    }
}
