using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validates the clean-room inner-image block walker and mount reconstruction against the
/// real Sony-built debug package (content id IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX, passcode
/// 12345678923456789102123901202333). Ground truth (FINDINGS.md §9.7): the inner mount is
/// 4,849,664 bytes (19 ublocks of 256 KiB), and the total compressed size of the walked
/// blocks is 197,371 bytes.
/// </summary>
public sealed class ProsperoPs5InnerImageReaderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";
    private const int ExpectedMountSize = 4_849_664;
    private const int ExpectedCompressedTotal = 197_371;
    private const int ExpectedBlockCount = 21;

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact]
    public void DebugPackage_WalkBlocks_MatchesGroundTruthGeometry()
    {
        (byte[] innerImage, byte[] naps) = ReadInnerImageAndNaps();

        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks =
            ProsperoPs5InnerImageReader.WalkBlocks(naps, innerImage.Length);

        long totalCompressed = 0;
        long totalUncompressed = 0;
        foreach (ProsperoPs5InnerImageReader.InnerBlock b in blocks)
        {
            totalCompressed += b.CompressedLength;
            totalUncompressed += b.UncompressedLength;
        }

        // nu=19 (header "ublocks") but the cbi walk pairs 22 STD entries into 21 blocks.
        // The authoritative ground truth is the walk totals (FINDINGS.md §9.7).
        Assert.Equal(19, ProsperoNapsLayout.DecodeHeader(naps).NumUBlocks);
        Assert.Equal(ExpectedBlockCount, blocks.Count);
        Assert.Equal(ExpectedCompressedTotal, totalCompressed);
        Assert.Equal(ExpectedMountSize, totalUncompressed);
    }

    [Fact]
    public void DebugPackage_ReconstructMount_MatchesGroundTruthSize()
    {
        (byte[] innerImage, byte[] naps) = ReadInnerImageAndNaps();

        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(innerImage, naps);

        Assert.Equal(ExpectedMountSize, mount.Length);

        // The debug inner mount packs a keystone and an ELF image; both should be recoverable.
        Assert.True(ContainsSequence(mount, "keystone"u8.ToArray()),
            "Reconstructed mount should contain the keystone magic.");
        Assert.True(ContainsSequence(mount, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' }),
            "Reconstructed mount should contain an ELF header.");
    }

    [Fact]
    public void WalkBlocks_UsesRunAnchorAbsoluteOffsetAndReconstructsExactBytes()
    {
        const int source = 0x45023; // >256KiB and carries a non-zero low 18-bit component
        byte[] image = new byte[source + 0x20000];
        byte[] expected = Enumerable.Range(0, 0x20000).Select(i => (byte)(i * 13)).ToArray();
        expected.CopyTo(image, source);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            NumUBlocks = 1, NumOuterBlocks = 2, FileLogicalOffsets = new long[] { 0, 0x20000 },
            Blocks = new NapsCblockPlanEntry[]
            {
                new() { StartRun = true, OnDiskOffset = source, LogicalOffset = 0, EvenChunkCompressedLength = 0x20000,
                    StreamLength = 0x20000, Even = 1, StoredRaw = true },
                new() { StartRun = true, OnDiskOffset = source + 0x20000, LogicalOffset = 0x20000, Terminator = true },
            },
        });
        ProsperoPs5InnerImageReader.InnerBlock block = ProsperoPs5InnerImageReader.WalkBlocks(naps, image.Length).Single();
        Assert.Equal(source, block.CompressedOffset);
        Assert.Equal(expected, ProsperoPs5InnerImageReader.ReconstructMount(image, naps).AsSpan(0, expected.Length).ToArray());
    }

    [Fact]
    public void ReconstructMount_ThrowsForStoredRangeOutsideSource()
    {
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            NumUBlocks = 1, NumOuterBlocks = 1, FileLogicalOffsets = new long[] { 0, 16 },
            Blocks = new NapsCblockPlanEntry[]
            {
                new() { StartRun = true, OnDiskOffset = 0x100, LogicalOffset = 0, EvenChunkCompressedLength = 16,
                    StreamLength = 16, Even = 1, StoredRaw = true },
                new() { StartRun = true, OnDiskOffset = 0x110, LogicalOffset = 16, Terminator = true },
            },
        });
        Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReconstructMount(new byte[8], naps));
    }

    [Fact]
    public void ReconstructMount_ReplaysNonZeroAliasAndThrowsForRequiredKrakenFailure()
    {
        byte[] image = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var aliasRequest = new NapsGenerationRequest
        {
            NumUBlocks = 1, NumOuterBlocks = 1, FileLogicalOffsets = new long[] { 0, 32 },
            Blocks = new NapsCblockPlanEntry[]
            {
                new() { StartRun = true, OnDiskOffset = 0, LogicalOffset = 0, EvenChunkCompressedLength = 16, StreamLength = 16, Even = 1, StoredRaw = true },
                new() { StartRun = true, OnDiskOffset = 0, LogicalOffset = 16, EvenChunkCompressedLength = 1, StreamLength = 0, Even = 1, IsAlias = true },
                new() { LogicalOffset = 32, Terminator = true },
            },
        };
        byte[] aliasMount = ProsperoPs5InnerImageReader.ReconstructMount(image, ProsperoNapsLayoutBuilder.Build(aliasRequest));
        Assert.Equal(aliasMount.AsSpan(0, 16).ToArray(), aliasMount.AsSpan(16, 16).ToArray());

        var krakenRequest = new NapsGenerationRequest
        {
            NumUBlocks = 1, NumOuterBlocks = 1, FileLogicalOffsets = new long[] { 0, 16 },
            Blocks = new NapsCblockPlanEntry[]
            {
                new() { StartRun = true, OnDiskOffset = 0, LogicalOffset = 0, EvenChunkCompressedLength = 1, StreamLength = 1, Even = 5, KdePredictor = 1 },
                new() { LogicalOffset = 16, Terminator = true },
            },
        };
        Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.ReconstructMount(new byte[] { 0 }, ProsperoNapsLayoutBuilder.Build(krakenRequest)));
    }

    [Fact]
    public void ReconstructRunEncryptedMount_UsesRunTweakCursor()
    {
        byte[] expected = Enumerable.Range(0, 0x100).Select(i => (byte)(i * 29)).ToArray();
        byte[] plainBlock = new byte[0x10000];
        expected.CopyTo(plainBlock, 0);
        byte[] dataKey = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] tweakKey = Enumerable.Range(16, 16).Select(i => (byte)i).ToArray();
        using var xts = new AesXts(dataKey, tweakKey);
        byte[] encrypted = xts.Encrypt(plainBlock, 0);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            NumUBlocks = 1,
            NumOuterBlocks = 1,
            FileLogicalOffsets = [0, expected.Length],
            Blocks =
            [
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = 0, LogicalOffset = 0,
                    EvenChunkCompressedLength = expected.Length, StreamLength = expected.Length,
                    Even = 1, StoredRaw = true,
                },
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = expected.Length,
                    LogicalOffset = expected.Length, Terminator = true,
                },
            ],
        });

        byte[] actual = ProsperoPs5InnerImageReader.ReconstructRunEncryptedMount(encrypted, naps, xts);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void WalkBlocks_DerivesSingleChunkKrakenFlagsFromEvenSelector()
    {
        // Even selector bit 2 = raw literals, bit 1 = delta literals; the decoder flag must mirror
        // both. A blind candidate search would try 0x02 (raw) before 0x03 (delta) and can silently
        // accept the wrong decode.
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 1, NumOuterBlocks = 2,
            FileLogicalOffsets = [0, 0x10],
            Blocks =
            [
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = 0x40000, LogicalOffset = 0,
                    EvenChunkCompressedLength = 1, StreamLength = 1, Even = 6, KdePredictor = 1,
                },
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = 0x40001, LogicalOffset = 0x10, Terminator = true,
                },
            ],
        });

        ProsperoPs5InnerImageReader.InnerBlock block =
            Assert.Single(ProsperoPs5InnerImageReader.WalkBlocks(naps, 0x10));

        Assert.True(block.IsKraken);
        Assert.Equal(0x03, block.KrakenFlags);
    }

    [Fact]
    public void WalkBlocks_DerivesMultiChunkKrakenFlagsFromEvenAndOddSelectors()
    {
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 1, NumOuterBlocks = 2,
            FileLogicalOffsets = [0, 0x30000],
            Blocks =
            [
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = 0x40000, LogicalOffset = 0,
                    EvenChunkCompressedLength = 1, StreamLength = 1, Even = 6, Odd = 6, KdePredictor = 1,
                },
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = 0x40001, LogicalOffset = 0x30000, Terminator = true,
                },
            ],
        });

        ProsperoPs5InnerImageReader.InnerBlock block =
            Assert.Single(ProsperoPs5InnerImageReader.WalkBlocks(naps, 0x30000));

        Assert.True(block.IsKraken);
        Assert.Equal(0x33, block.KrakenFlags);
    }

    [Fact]
    public void WalkBlocks_UsesRunAnchorWhenMarkerAbsentButRunPageNonZero()
    {
        // Reference-writer packages carry no clean-room stored marker (Raw[8]&0x08) yet re-base the
        // compressed cursor through a RUN page above 256 KiB. They must take the modern RUN-anchored
        // path, not the legacy low-18-bit cursor.
        const long source = 0x40000;
        byte[] image = new byte[source + 0x20];
        byte[] expected = Enumerable.Range(0, 0x10).Select(i => (byte)(i * 11 + 1)).ToArray();
        expected.CopyTo(image, source);

        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 1, NumOuterBlocks = 2,
            FileLogicalOffsets = [0, 0x10],
            Blocks =
            [
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = source, LogicalOffset = 0,
                    EvenChunkCompressedLength = 0x10, StreamLength = 0x10, Even = 1, KdePredictor = 1,
                },
                new NapsCblockPlanEntry
                {
                    StartRun = true, OnDiskOffset = source + 0x10, LogicalOffset = 0x10, Terminator = true,
                },
            ],
        });

        ProsperoPs5InnerImageReader.InnerBlock block =
            Assert.Single(ProsperoPs5InnerImageReader.WalkBlocks(naps, image.Length));
        Assert.Equal(source, block.CompressedOffset);
        Assert.Equal(expected,
            ProsperoPs5InnerImageReader.ReconstructMount(image, naps).AsSpan(0, expected.Length).ToArray());
    }

    private static (byte[] InnerImage, byte[] Naps) ReadInnerImageAndNaps()
    {
        using var stream = File.OpenRead(Fixture("test.pkg"));
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        OuterPfsReader pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        byte[] naps = pfs.ReadNaps(xts);
        byte[] innerImage = pfs.ReadInnerImage(xts);
        return (innerImage, naps);
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j])
                j++;
            if (j == needle.Length)
                return true;
        }
        return false;
    }
}
