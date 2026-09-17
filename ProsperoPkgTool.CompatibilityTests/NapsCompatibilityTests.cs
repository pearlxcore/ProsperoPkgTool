using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class NapsCompatibilityTests
{
    [Fact]
    public void Lpp120MixedFixture_ReadsExactPayloadThroughBothReaders()
    {
        string package = Path.Combine(AppContext.BaseDirectory, "Fixtures", "lpp120-mixed.pkg");
        var decoded = ProsperoPackageContent.Read(package);
        using var lazy = ProsperoPackageContent.ReadFileBacked(package);
        Assert.Equal("native-span-v1", Assert.IsType<NapsBlockPlan>(lazy.Blocks).Dialect);
        Assert.Equal(13_238_272, lazy.MountLength);
        Assert.Equal(7, lazy.Entries.Count(e => !e.IsDirectory));
        Assert.Contains(lazy.Blocks, b => b.IsZeroHole);
        Assert.Contains(lazy.Blocks, b => b.IsKraken);
        Assert.Contains(lazy.Blocks, b => !b.IsKraken && !b.IsZeroHole && b.UncompressedLength == 0x40000);
        var entry = Assert.Single(lazy.Entries, e => e.Path == "/uroot/payload.bin");
        Assert.Equal(8 * 1024 * 1024, entry.Size);
        byte[] expected = new byte[entry.Size];
        new Random(42).NextBytes(expected.AsSpan(0, 1024 * 1024));
        for (int i = 2 * 1024 * 1024; i < 4 * 1024 * 1024; i++) expected[i] = (byte)(i * 31);
        Assert.Equal(expected, ProsperoInnerPfsReader.ReadFile(decoded.Mount, entry));
        using var mount = lazy.OpenMount();
        using var full = new MemoryStream();
        mount.CopyTo(full);
        Assert.Equal(decoded.Mount, full.ToArray());
        lazy.DecodeAllBlocks();
        Assert.False(ProsperoPackageContent.RequiresFileBacked(package));
    }

    [Fact]
    public void UnmarkedFullStoredSpan_IsNotAnUnresolvedAlias()
    {
        byte[] image = new byte[0x80000];
        new Random(7).NextBytes(image.AsSpan(0x40000));
        byte[] naps = MakeFullStoredLayout();
        var block = Assert.Single(ProsperoPs5InnerImageReader.WalkBlocks(naps, image.Length));
        Assert.False(block.IsAlias);
        Assert.False(block.IsKraken);
        Assert.Equal(0x40000, block.CompressedOffset);
        Assert.Equal(image.AsSpan(0x40000).ToArray(), ProsperoPs5InnerImageReader.ReconstructMount(image, naps));
    }

    [Fact]
    public void UnmarkedFullStoredSpan_OutsideSourceFails()
    {
        var error = Assert.Throws<InvalidDataException>(() =>
            ProsperoPs5InnerImageReader.WalkBlocks(MakeFullStoredLayout(), 0x40000));
        Assert.Contains("source outside image", error.Message);
    }

    [Fact]
    public void TruncatedCblockTable_FailsInsteadOfReturningAPartialMount()
    {
        byte[] naps = MakeFullStoredLayout();
        int end = checked((int)ProsperoNapsLayout.ComputeCblockInfoBase(naps) +
            ProsperoNapsLayout.DecodeHeader(naps).NumCblockInfo * 9);
        Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps[..(end - 1)], 0x80000));
    }

    [Fact]
    public void EncodedZeroSpan_AdvancesSourceBeforeFollowingStoredBytes()
    {
        byte[] image = new byte[0x80018];
        byte[] tail = [1, 2, 3, 4, 5, 6, 7, 8];
        tail.CopyTo(image, 0x80010);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 3, NumOuterBlocks = 9, FileLogicalOffsets = [0, 0x80008],
            Blocks =
            [
                new() { StartRun = true, OnDiskOffset = 0x40000, LogicalOffset = 0,
                    EvenChunkCompressedLength = 0x20000, StreamLength = 0x40000, Even = 1, Odd = 1 },
                new() { LogicalOffset = 0x40000, EvenChunkCompressedLength = 8, StreamLength = 16, Even = 1, Odd = 1 },
                new() { LogicalOffset = 0x80000, EvenChunkCompressedLength = 8, StreamLength = 8, Even = 1 },
                new() { LogicalOffset = 0x80008, Terminator = true },
            ]
        });
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(image, naps);
        Assert.Equal(tail, mount.AsSpan(0x80000, 8).ToArray());
        Assert.All(mount.AsSpan(0x40000, 0x40000).ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void DifferentPlausibleMaps_RequireMetadataInsteadOfGuessing()
    {
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 2, NumOuterBlocks = 5, FileLogicalOffsets = [0, 0x40008],
            Blocks =
            [
                new() { StartRun = true, OnDiskOffset = 0x40000, LogicalOffset = 0,
                    EvenChunkCompressedLength = 8, StreamLength = 16, Even = 1, Odd = 1 },
                new() { LogicalOffset = 0x40000, EvenChunkCompressedLength = 8, StreamLength = 8, Even = 1 },
                new() { LogicalOffset = 0x40008, Terminator = true },
            ]
        });
        var error = Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps, 0x40018));
        Assert.Contains("Ambiguous", error.Message);
    }

    [Fact]
    public void ConsecutiveRunsWithoutStd_Fail()
    {
        byte[] naps = MakeFullStoredLayout();
        int start = checked((int)ProsperoNapsLayout.ComputeCblockInfoBase(naps));
        naps.AsSpan(start, 9).CopyTo(naps.AsSpan(start + 9, 9));
        Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps, 0x80000));
    }

    [Theory]
    [InlineData(0x7FFF0000L)]
    [InlineData(0x80000000L)]
    public void LogicalMountSize_UsesLongAcrossTwoGiBBoundary(long length)
    {
        var blocks = new[] { new ProsperoPs5InnerImageReader.InnerBlock(0, 0, 0, length - 0x10000, 0x10000, false, true) };
        using var mount = new ProsperoInnerMountStream(blocks, 0, (_, _) => throw new Exception("Zero fill must not read source bytes."));
        Assert.Equal(length, mount.Length);
        mount.Position = length - 1;
        Assert.Equal(0, mount.ReadByte());
        Assert.Equal(-1, mount.ReadByte());
    }

    private static byte[] MakeFullStoredLayout() => ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
    {
        CompressionType = 2, NumUBlocks = 1, NumOuterBlocks = 8,
        FileLogicalOffsets = [0, 0x40000],
        Blocks =
        [
            new() { StartRun = true, OnDiskOffset = 0x40000, LogicalOffset = 0,
                EvenChunkCompressedLength = 0x20000, StreamLength = 0x40000, Even = 1, Odd = 1 },
            new() { StartRun = true, OnDiskOffset = 0x80000, LogicalOffset = 0x40000, Terminator = true },
        ]
    });
}
