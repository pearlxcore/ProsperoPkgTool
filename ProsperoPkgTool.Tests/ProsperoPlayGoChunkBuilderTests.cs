using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoPlayGoChunkBuilderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";

    [Fact]
    public void OneChunkOneScenario_UsesTwoSeparateChunkZeroRuns()
    {
        ProsperoPlayGoChunkBuildResult result = Build(Project(1, 1), [MakeLeaf("/a.bin", 0, 0x10000)]);

        Assert.Equal([(0UL, 0x70000UL, 0), (0x70000UL, 0x20000UL, 0)],
            result.Extents.Select(e => (e.Start, e.Length, e.ChunkId)));
        Assert.Equal([0U, 1U], result.ChunkExtentIds[0]);
        Assert.Equal(0x100u, U32(result.Data, 0xc0));
        Assert.Equal(0x120u, U32(result.Data, 0xc8));
        Assert.Equal(8u, U32(result.Data, 0xc8 + 4));
        Assert.Equal((uint)result.Data.Length, U32(result.Data, 0x10));
        Assert.Equal(result.Data, ProsperoPlayGoChunkBuilder.Build(ContentId, Project(1, 1), Image([MakeLeaf("/a.bin", 0, 0x10000)]), 0x10000, 0x90000).Data);
    }

    [Fact]
    public void ChunkZeroChunkOneChunkZero_DerivesPhysicalOrderC8AndD8()
    {
        Leaf[] leaves = [MakeLeaf("/a.bin", 0, 0x10000), MakeLeaf("/b.bin", 0x30000, 0x10000), MakeLeaf("/c.bin", 0x40000, 0x10000)];
        ProsperoPlayGoChunkBuildResult result = Build(Project(2, 1), leaves,
            new Dictionary<string, byte> { ["/b.bin"] = 1 });

        Assert.Equal([(0UL, 0x40000UL, 0), (0x40000UL, 0x10000UL, 1), (0x50000UL, 0x20000UL, 0), (0x70000UL, 0x20000UL, 0)],
            result.Extents.Select(e => (e.Start, e.Length, e.ChunkId)));
        Assert.Equal([0U, 2U, 3U], result.ChunkExtentIds[0]);
        Assert.Equal([1U], result.ChunkExtentIds[1]);
        int c8 = 0x100 + 2 * 0x20;
        Assert.Equal([0U, 2U, 3U, 1U], Enumerable.Range(0, 4).Select(i => U32(result.Data, c8 + i * 4)));
        int d8 = checked((int)U32(result.Data, 0xd8));
        Assert.Equal(0x40000UL, U64(result.Data, d8 + 16));
        Assert.Equal(0x10000UL, U64(result.Data, d8 + 24));
    }

    [Fact]
    public void UnusedChunk_HasNoExtentIds_AndTwoScenariosSerializeSequences()
    {
        ProsperoPlayGoChunkBuildResult result = Build(Project(3, 2), [MakeLeaf("/a.bin", 0, 0x10000)],
            new Dictionary<string, byte> { ["/a.bin"] = 1 });
        PlayGoProject parsed = PlayGoChunkReader.Read(result.Data);

        Assert.Empty(result.ChunkExtentIds[2]);
        Assert.Equal([0U, 2U], result.ChunkExtentIds[0]);
        Assert.Equal([1U], result.ChunkExtentIds[1]);
        Assert.Equal(2, parsed.Scenarios.Count);
        Assert.Equal([0, 1], parsed.Scenarios[1].Chunks);
        Assert.Equal(1, parsed.Scenarios[1].InitialChunkCount);
    }

    [Fact]
    public void GeneratedKeystoneRightSprxNestedAndZeroLength_DefaultToChunkZero()
    {
        Leaf[] leaves = [
            MakeLeaf("/sce_sys/keystone", 0, 0x10000),
            MakeLeaf("/sce_sys/about/right.sprx", 0x10000, 0x10000),
            MakeLeaf("/nested/data.bin", 0x20000, 0x10000),
            MakeLeaf("/empty.bin", 0x30000, 0),
        ];
        ProsperoPlayGoChunkBuildResult result = Build(Project(2, 1), leaves,
            new Dictionary<string, byte> { ["nested/data.bin"] = 1 });

        // The zero-length leaf has no physical ownership run; generated files stay chunk 0.
        Assert.Equal([(0UL, 0x30000UL, 0), (0x30000UL, 0x40000UL, 1), (0x70000UL, 0x20000UL, 0)],
            result.Extents.Select(e => (e.Start, e.Length, e.ChunkId)));
    }

    [Fact]
    public void LargeFileBoundaryAndSectionDirectory_AreDeterministic()
    {
        ProsperoPlayGoChunkBuildResult result = Build(Project(2, 2),
            [MakeLeaf("/large.bin", 0, 0xE1000), MakeLeaf("/later.bin", 0xF0000, 0x10000)],
            new Dictionary<string, byte> { ["/later.bin"] = 1 }, metadataOffset: 0x100000, cntOffset: 0x120000);

        Assert.Equal(0x10000UL + 0xF0000UL, result.Extents[1].Start);
        Assert.Equal(0x10000UL, result.Extents[1].Length);
        Assert.Equal((uint)result.Data.Length, U32(result.Data, 0x10));
        Assert.Equal(0u, U32(result.Data, 0xf8 + 4)); // F8 remains empty.
    }

    [Fact]
    public void AssignmentValidation_RejectsUnknownGeneratedAndUndefinedChunkPaths()
    {
        Leaf[] leaves = [MakeLeaf("/a.bin", 0, 0x10000), MakeLeaf("/sce_sys/keystone", 0x10000, 0x10000)];
        Assert.Throws<InvalidDataException>(() => Build(Project(2, 1), leaves,
            new Dictionary<string, byte> { ["missing.bin"] = 1 }));
        Assert.Throws<InvalidDataException>(() => Build(Project(2, 1), leaves,
            new Dictionary<string, byte> { ["a.bin"] = 2 }));
        Assert.Throws<InvalidDataException>(() => Build(Project(2, 1), leaves,
            new Dictionary<string, byte> { ["sce_sys/keystone"] = 1 }));
    }

    private static ProsperoPlayGoChunkBuildResult Build(PlayGoProject project, Leaf[] leaves,
        IReadOnlyDictionary<string, byte>? assignments = null, long metadataOffset = 0x60000, ulong cntOffset = 0x90000) =>
        ProsperoPlayGoChunkBuilder.Build(ContentId, project, Image(leaves, metadataOffset), 0x10000, cntOffset, assignments);

    private static ProsperoInnerImageAssembler.InnerImageResult Image(Leaf[] leaves, long metadataOffset = 0x60000) => new()
    {
        Image = [], MetadataPlaintext = [], CompressedMetadata = [], MetadataBlocks = [], Ndblock = 1,
        MetaBaseLogical = 0, DataEndLogical = 0, BlockInfoOnDiskOffset = 0, MetadataOnDiskOffset = metadataOffset,
        Nodes = leaves.Select((l, i) => new ProsperoInnerImageAssembler.MetaNodeInfo { FullPath = l.Path, Afid = (uint)i, Size = l.Size }).ToList(),
        Placements = leaves.Select(l => new ProsperoInnerImageAssembler.Placement(l.Offset, 0, l.Size, l.Size, true)).ToList(),
        AfidLogicalOffsets = leaves.Select(_ => 0L).ToList(), InodeCount = leaves.Length, InnerContentInodes = leaves.Length, AppFileCount = leaves.Length,
    };

    private static PlayGoProject Project(int chunks, int scenarios) => new()
    {
        VersionMajor = 0x1000, ContentId = ContentId, DefaultScenarioId = 0,
        Chunks = Enumerable.Range(0, chunks).Select(i => new PlayGoChunk(i, $"Chunk #{i}", ulong.MaxValue)).ToList(),
        Scenarios = Enumerable.Range(0, scenarios).Select(i => new PlayGoScenario(i, $"Scenario #{i}", 1,
            i == 0 ? [0] : Enumerable.Range(0, Math.Min(chunks, i + 1)).ToList())).ToList(),
    };

    private static Leaf MakeLeaf(string path, long offset, long size) => new(path, offset, size);
    private static uint U32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset));
    private static ulong U64(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset));
    private readonly record struct Leaf(string Path, long Offset, long Size);
}
