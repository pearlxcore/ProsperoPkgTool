using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Content;

namespace ProsperoPkgTool.Tests;

public sealed class NapsSparseIndexTests
{
    private sealed class MemoryFileSource(byte[] bytes) : IProsperoFileSource
    {
        public long Length => bytes.Length;
        public Stream Open() => new MemoryStream(bytes, writable: false);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    public void WholePageGaps_RestorePositionsWithoutInflatingPayloads(int missingPages)
    {
        byte[] naps = SparseMap(missingPages);
        byte[] image = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var blocks = ProsperoPs5InnerImageReader.WalkBlocks(naps, image.Length);
        Assert.Equal("indexed-coffset-v1", Assert.IsType<NapsBlockPlan>(blocks).Dialect);
        Assert.Equal(missingPages, blocks.Count(b => b.IsZeroHole));
        Assert.All(blocks.Where(b => !b.IsZeroHole), b => Assert.Equal(16, b.UncompressedLength));
        byte[] materialized = ProsperoPs5InnerImageReader.ReconstructMount(image, naps);
        long second = missingPages * 0x40000L + 16;
        Assert.Equal(image[..16], materialized[..16]);
        Assert.Equal(image[16..], materialized.AsSpan((int)second, 16).ToArray());
        // Alias source was block 1 before inserting holes; it must now resolve past the holes.
        Assert.Equal(missingPages + 1, blocks[^1].SourceBlockIndex);
        Assert.Equal(image[16..], materialized.AsSpan((int)second + 16, 16).ToArray());
        using var lazy = new ProsperoInnerMountStream(blocks, image.Length,
            (offset, length) => image.AsSpan((int)offset, length).ToArray());
        byte[] actual = new byte[second + 32];
        lazy.ReadExactly(actual);
        Assert.Equal(materialized[..actual.Length], actual);
        Assert.Equal(-1, actual.AsSpan(16, missingPages * 0x40000).IndexOfAnyExcept((byte)0));
    }

    [Fact]
    public void IncorrectU2cAnchor_CannotMoveTheGapBeforeTheFirstFile()
    {
        byte[] naps = SparseMap(1);
        int u2c = (int)ProsperoNapsLayout.ComputeU2cOffset(ProsperoNapsLayout.DecodeHeader(naps));
        naps[u2c + 3] = 0; // page 1 now points at STD 1 instead of STD 2
        var error = Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps, 32));
        Assert.Contains("fidx", error.Message);
    }

    [Fact]
    public void U2cAnchorToRun_IsRejected()
    {
        byte[] naps = SparseMap(1);
        int u2c = (int)ProsperoNapsLayout.ComputeU2cOffset(ProsperoNapsLayout.DecodeHeader(naps));
        naps[u2c + 3] = 2; // base STD 1 + 2 points at the alias RUN
        var error = Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps, 32));
        Assert.Contains("Invalid NAPS u2c STD anchor", error.Message);
    }

    [Fact]
    public void WrongFidxBoundary_IsRejectedInsteadOfPaddingTheEnd()
    {
        byte[] naps = SparseMap(1);
        var section = ProsperoNapsLayout.SectionMap(ProsperoNapsLayout.DecodeHeader(naps)).UncompressedOffsetStartByFileIdx;
        naps[(int)section.Offset + 6] ^= 1;
        var error = Assert.Throws<InvalidDataException>(() => ProsperoPs5InnerImageReader.WalkBlocks(naps, 32));
        Assert.Contains("fidx", error.Message);
    }

    [Fact]
    public void ManySmallFiles_RoundTripAcrossSparseAfidSlots()
    {
        string root = Path.Combine(Path.GetTempPath(), "NapsSparseIndex-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var expected = Enumerable.Range(0, 100).ToDictionary(i => $"/data/{i:D3}.bin",
                i => Enumerable.Range(0, 333 + i).Select(j => (byte)(i + j * 13)).ToArray());
            var files = expected.Select(pair => new ProsperoInnerImageAssembler.InnerFile
            {
                Path = pair.Key, Source = new MemoryFileSource(pair.Value), Length = pair.Value.Length
            }).ToList();
            string path = Path.Combine(root, "sparse.pkg");
            ProsperoDebugPackageBuilder.Build(files, new DebugPackageBuildOptions
            {
                OutputPath = path, ContentId = "UP0000-PPSA12345_00-TESTPACKAGE00000",
                Passcode = new string('0', 32),
                ParamJson = """{"contentId":"UP0000-PPSA12345_00-TESTPACKAGE00000","titleId":"PPSA12345"}"""u8.ToArray(),
                FakeSignModules = false, InjectRightSprx = false, OuterSeed = new byte[16],
                SweepStaleTempWorkspaces = false
            });
            var memory = ProsperoPackageContent.Read(path);
            using var lazy = ProsperoPackageContent.ReadFileBacked(path);
            Assert.Equal("indexed-coffset-v1", Assert.IsType<NapsBlockPlan>(lazy.Blocks).Dialect);
            using var mount = lazy.OpenMount();
            foreach (var pair in expected)
            {
                var entry = Assert.Single(lazy.Entries, e => e.Path == "/uroot" + pair.Key);
                Assert.Equal(pair.Value, ProsperoInnerPfsReader.ReadFile(memory.Mount, entry));
                using var output = new MemoryStream();
                ProsperoInnerPfsReader.ExtractFile(mount, entry, output);
                Assert.Equal(pair.Value, output.ToArray());
            }
            lazy.DecodeAllBlocks();
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static byte[] SparseMap(int pages)
    {
        long second = pages * 0x40000L + 16;
        return ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = pages + 1, NumOuterBlocks = 1,
            FileLogicalOffsets = [0, second, second + 16, second + 32],
            Blocks =
            [
                new() { StartRun = true, OnDiskOffset = 0, LogicalOffset = 0,
                    EvenChunkCompressedLength = 16, StreamLength = 16, Even = 1, StoredRaw = true },
                new() { OnDiskOffset = 16, LogicalOffset = second,
                    EvenChunkCompressedLength = 16, StreamLength = 16, Even = 1, StoredRaw = true },
                new() { StartRun = true, OnDiskOffset = 16, LogicalOffset = second + 16,
                    EvenChunkCompressedLength = 1, StreamLength = 0, Even = 1, IsAlias = true },
                new() { LogicalOffset = second + 32, Terminator = true },
            ]
        });
    }
}
