using System.Buffers.Binary;
using System.Text;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Containers;

/// <summary>One debug/nwonly outer-package ownership extent in a PLGX descriptor.</summary>
public readonly record struct ProsperoPlayGoExtent(ulong Start, ulong Length, int ChunkId);

/// <summary>The serialized descriptor plus its independently useful ownership derivation.</summary>
public sealed class ProsperoPlayGoChunkBuildResult
{
    public required byte[] Data { get; init; }
    public required IReadOnlyList<ProsperoPlayGoExtent> Extents { get; init; }
    public required IReadOnlyList<IReadOnlyList<uint>> ChunkExtentIds { get; init; }
}

/// <summary>
/// Clean-room serializer for the observed debug/nwonly <c>playgo-chunk.dat</c> (PLGX) format.
/// It consumes finalized inner-image placement semantics; it does not consume or transform a
/// prebuilt PLGX byte stream and deliberately makes no retail/general compatibility claim.
/// </summary>
public static class ProsperoPlayGoChunkBuilder
{
    public const int HeaderSize = 0x100;
    private const int RecordSize = 0x20;
    private const uint Magic = 0x78676c70; // "plgx", little endian
    private const uint DebugRecordFlags = 0x00030080;
    private const uint DebugRecordUse = 0x11;
    private const uint DebugHeaderFlags = 0x85;
    private const uint DebugHeaderUse = 4;
    private const uint DebugHeaderUnknown = 0x11;
    private const int OuterBlockSize = 0x10000;

    /// <summary>Creates the documented source-folder default: one chunk and one scenario.</summary>
    public static PlayGoProject CreateDefaultProject(string contentId) => new()
    {
        VersionMajor = 0x1000,
        VersionMinor = 0,
        ContentId = contentId,
        DefaultScenarioId = 0,
        Chunks = [new PlayGoChunk(0, "Chunk #0", ulong.MaxValue)],
        Scenarios = [new PlayGoScenario(0, "Scenario #0", 1, [0])],
    };

    /// <summary>
    /// Creates a project with <paramref name="chunkCount"/> chunks in a single scenario. The verified
    /// clean-room default is one chunk; higher counts are structural and unverified against a
    /// publisher reference (every inner file still defaults to chunk zero unless an explicit
    /// assignment is supplied), so they are opt-in.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The count is outside 1..255.</exception>
    public static PlayGoProject CreateProject(string contentId, int chunkCount)
    {
        if (chunkCount <= 1)
            return CreateDefaultProject(contentId);
        if (chunkCount > byte.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(chunkCount), chunkCount,
                "PlayGo chunk count must be in the range 1..255.");

        var chunks = new List<PlayGoChunk>(chunkCount);
        var scenarioChunks = new List<int>(chunkCount);
        for (int i = 0; i < chunkCount; i++)
        {
            chunks.Add(new PlayGoChunk(i, $"Chunk #{i}", ulong.MaxValue));
            scenarioChunks.Add(i);
        }
        return new PlayGoProject
        {
            VersionMajor = 0x1000,
            VersionMinor = 0,
            ContentId = contentId,
            DefaultScenarioId = 0,
            Chunks = chunks,
            Scenarios = [new PlayGoScenario(0, "Scenario #0", 1, scenarioChunks)],
        };
    }

    /// <summary>
    /// Builds PLGX and derives D8/C8 from final inner on-disk placements. Assignment keys are
    /// normalized inner paths; absent entries, including generated keystone/right.sprx, are chunk 0.
    /// </summary>
    public static ProsperoPlayGoChunkBuildResult Build(
        string contentId,
        PlayGoProject project,
        ProsperoInnerImageAssembler.InnerImageResult inner,
        ulong fihPfsOffset,
        ulong fihCntOffset,
        IReadOnlyDictionary<string, byte>? chunkAssignments = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentId);
        ArgumentNullException.ThrowIfNull(project);
        ArgumentNullException.ThrowIfNull(inner);
        ValidateProject(contentId, project);
        if (fihPfsOffset % OuterBlockSize != 0 || fihCntOffset <= fihPfsOffset)
            throw new ArgumentException("PLGX requires ordered 64-KiB-aligned FIH PFS/CNT offsets.");

        Dictionary<string, byte> assignments = NormalizeAssignments(inner,
            chunkAssignments ?? project.FileChunkAssignments, project.Chunks.Count);
        List<PhysicalLeaf> leaves = BuildPhysicalLeaves(inner, assignments);
        List<ProsperoPlayGoExtent> extents = DeriveExtents(leaves, inner.MetadataOnDiskOffset,
            fihPfsOffset, fihCntOffset);
        var extentIds = Enumerable.Range(0, project.Chunks.Count).Select(_ => new List<uint>()).ToArray();
        for (int i = 0; i < extents.Count; i++)
            extentIds[extents[i].ChunkId].Add((uint)i);

        // The observed debug/nwonly container carries a fixed single-chunk/single-scenario profile
        // with two mchunk regions tiling the mount image up to cnt_offset. Byte-verified against the
        // Sony fixture; richer projects keep the variable-length extent serializer below.
        if (project.Chunks.Count == 1 && project.Scenarios.Count == 1)
        {
            long innerSize = inner.ImageSize;
            long aligned = innerSize <= 0
                ? 0
                : (innerSize + OuterBlockSize - 1) / OuterBlockSize * OuterBlockSize;
            ulong total = fihCntOffset;
            ulong mchunk0 = aligned > 0 && (ulong)aligned < total
                ? (ulong)aligned
                : total - (ulong)OuterBlockSize;
            ulong mchunk1 = total - mchunk0;
            return new ProsperoPlayGoChunkBuildResult
            {
                Data = BuildSingleChunkProfile(contentId, project.Chunks[0].LanguageMask, mchunk0, mchunk1),
                Extents = extents,
                ChunkExtentIds = extentIds,
            };
        }

        byte[] chunkLabels = EncodeLabels(project.Chunks.Select(c => c.Label));
        byte[] scenarioLabels = EncodeLabels(project.Scenarios.Select(s => s.Label));
        int c8Size = checked(extents.Count * sizeof(uint));
        int d0 = checked(HeaderSize + project.Chunks.Count * RecordSize + c8Size);
        int d8 = checked(d0 + chunkLabels.Length);
        int e0 = checked(d8 + extents.Count * 16);
        int e8 = checked(e0 + project.Scenarios.Count * RecordSize);
        int sequenceItems = checked(project.Scenarios.Sum(s => s.Chunks.Count));
        int f0 = checked(e8 + sequenceItems * sizeof(ushort));
        int f8 = checked(f0 + scenarioLabels.Length);
        byte[] data = new byte[f8]; // F8 is empty in the scoped debug/nwonly model.

        WriteHeader(data, contentId, project, d0, d8, e0, e8, f0, f8, c8Size, chunkLabels.Length,
            extents.Count * 16, sequenceItems * 2, scenarioLabels.Length);
        int c8 = HeaderSize + project.Chunks.Count * RecordSize;
        int listOffset = 0;
        for (int i = 0; i < project.Chunks.Count; i++)
        {
            int at = HeaderSize + i * RecordSize;
            PlayGoChunk chunk = project.Chunks[i];
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at), DebugRecordFlags);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 4), (uint)extentIds[i].Count);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 8), DebugRecordUse);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(at + 0x10), chunk.LanguageMask);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 0x18), (uint)listOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 0x1c), (uint)LabelOffset(project.Chunks, i));
            foreach (uint id in extentIds[i])
            {
                BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(c8 + listOffset), id);
                listOffset += sizeof(uint);
            }
        }
        chunkLabels.CopyTo(data.AsSpan(d0));
        for (int i = 0; i < extents.Count; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(d8 + i * 16), extents[i].Start);
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(d8 + i * 16 + 8), extents[i].Length);
        }
        int sequenceOffset = 0;
        for (int i = 0; i < project.Scenarios.Count; i++)
        {
            PlayGoScenario scenario = project.Scenarios[i];
            int at = e0 + i * RecordSize;
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at), 0x21);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(at + 0x14), (ushort)scenario.InitialChunkCount);
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(at + 0x16), (ushort)scenario.Chunks.Count);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 0x18), (uint)sequenceOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 0x1c), (uint)LabelOffset(project.Scenarios, i));
            foreach (int chunkId in scenario.Chunks)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(e8 + sequenceOffset), (ushort)chunkId);
                sequenceOffset += sizeof(ushort);
            }
        }
        scenarioLabels.CopyTo(data.AsSpan(f0));
        return new ProsperoPlayGoChunkBuildResult { Data = data, Extents = extents, ChunkExtentIds = extentIds };
    }

    /// <summary>
    /// Serializes the fixed 0x1A0-byte single-chunk PLGX profile the debug/nwonly containers carry
    /// (byte-verified against the Sony fixture): one chunk, one scenario, one image, and two mchunk
    /// regions tiling the mount image up to cnt_offset.
    /// </summary>
    private static byte[] BuildSingleChunkProfile(string contentId, ulong languageMask, ulong mchunk0, ulong mchunk1)
    {
        byte[] d = new byte[0x1A0];
        BinaryPrimitives.WriteUInt32LittleEndian(d, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(4), 0x1000);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0xa), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0xe), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(0x10), 0x1A0);
        BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(0x16), 1);
        d[0x1e] = 0x85;
        d[0x20] = 0x02;
        d[0x24] = 0x01;
        d[0x30] = 0x11;
        d.AsSpan(0x38, 8).Fill(0xFF);
        Encoding.ASCII.GetBytes(contentId).CopyTo(d.AsSpan(0x40));
        WriteSection(d, 0xc0, 0x100, 0x20);
        WriteSection(d, 0xc8, 0x120, 0x08);
        WriteSection(d, 0xd0, 0x130, 0x09);
        WriteSection(d, 0xd8, 0x140, 0x20);
        WriteSection(d, 0xe0, 0x160, 0x20);
        WriteSection(d, 0xe8, 0x180, 0x02);
        WriteSection(d, 0xf0, 0x190, 0x0c);
        d[0x100] = 0x80;
        d[0x102] = 0x03;
        d[0x104] = 0x02;
        d[0x108] = 0x11;
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x110), languageMask);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(0x124), 1);
        Encoding.ASCII.GetBytes("Chunk #0\0").CopyTo(d.AsSpan(0x130));
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x140), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x148), mchunk0);
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x150), mchunk0);
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x158), mchunk1);
        BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(0x160), 0x21);
        d[0x174] = 1;
        d[0x176] = 1;
        Encoding.ASCII.GetBytes("Scenario #0\0").CopyTo(d.AsSpan(0x190));
        return d;
    }

    private static List<ProsperoPlayGoExtent> DeriveExtents(IReadOnlyList<PhysicalLeaf> leaves,
        long metadataOnDiskOffset, ulong pfsOffset, ulong cntOffset)
    {
        if (metadataOnDiskOffset < 0)
            throw new InvalidDataException("Inner metadata on-disk offset is invalid.");
        ulong metadata = checked(pfsOffset + (ulong)metadataOnDiskOffset);
        if (metadata > cntOffset || metadata % OuterBlockSize != 0)
            throw new InvalidDataException("PLGX metadata boundary is outside FIH PFS/CNT geometry or not 64-KiB aligned.");
        ulong start = 0;
        int owner = 0;
        var result = new List<ProsperoPlayGoExtent>();
        foreach (PhysicalLeaf leaf in leaves.Where(l => l.OnDiskSize > 0).OrderBy(l => l.OnDiskOffset))
        {
            if (leaf.ChunkId == owner)
                continue;
            ulong boundary = checked(pfsOffset + (ulong)leaf.OnDiskOffset);
            if (boundary % OuterBlockSize != 0)
                throw new InvalidDataException("A non-zero PlayGo chunk transition must begin at a 64-KiB physical inner boundary.");
            AddExtent(result, start, boundary, owner);
            start = boundary;
            owner = leaf.ChunkId;
        }
        AddExtent(result, start, metadata, owner);
        // The metadata/CNT tail is intentionally a separate c0 extent, even following c0.
        AddExtent(result, metadata, cntOffset, 0);
        return result;
    }

    private static void AddExtent(List<ProsperoPlayGoExtent> extents, ulong start, ulong end, int owner)
    {
        if (end <= start || (end - start) % OuterBlockSize != 0)
            throw new InvalidDataException("PLGX ownership extent is not a positive 64-KiB range.");
        extents.Add(new ProsperoPlayGoExtent(start, end - start, owner));
    }

    private static List<PhysicalLeaf> BuildPhysicalLeaves(ProsperoInnerImageAssembler.InnerImageResult inner,
        IReadOnlyDictionary<string, byte> assignments)
    {
        // Afids are sparse (holes) and empty files share a sentinel afid, so map by afid rather
        // than indexing the compact placement list; only byte-backed leaves carry a placement.
        var byAfid = inner.Placements.ToDictionary(p => p.Afid);
        return inner.Nodes.Where(n => !n.IsDirectory && n.FullPath.Length != 0 && n.Size > 0)
            .Select(n =>
            {
                ProsperoInnerImageAssembler.Placement placement = byAfid[n.Afid];
                return new PhysicalLeaf(placement.OnDiskOffset, placement.OnDiskSize,
                    assignments.TryGetValue(ProsperoPlayGoRecordBuilder.NormalizePath(n.FullPath), out byte id) ? id : (byte)0);
            })
            .ToList();
    }

    private static Dictionary<string, byte> NormalizeAssignments(ProsperoInnerImageAssembler.InnerImageResult inner,
        IReadOnlyDictionary<string, byte>? assignments, int chunkCount)
    {
        var result = new Dictionary<string, byte>(StringComparer.Ordinal);
        if (assignments is null) return result;
        var leaves = inner.Nodes.Where(n => !n.IsDirectory && n.FullPath.Length != 0)
            .Select(n => ProsperoPlayGoRecordBuilder.NormalizePath(n.FullPath)).ToHashSet(StringComparer.Ordinal);
        foreach ((string path, byte chunk) in assignments)
        {
            string normalized = ProsperoPlayGoRecordBuilder.NormalizePath(path);
            if (normalized is "SCE_SYS/KEYSTONE" or "SCE_SYS/ABOUT/RIGHT.SPRX" && chunk != 0)
                throw new InvalidDataException($"Generated PlayGo leaf '{path}' is fixed to chunk zero.");
            if (chunk >= chunkCount || !leaves.Contains(normalized))
                throw new InvalidDataException($"Invalid PlayGo assignment '{path}' -> {chunk}.");
            result.Add(normalized, chunk);
        }
        return result;
    }

    private static void ValidateProject(string contentId, PlayGoProject project)
    {
        if (project.Chunks.Count is < 1 or > byte.MaxValue || project.Scenarios.Count is < 1 or > ushort.MaxValue ||
            project.DefaultScenarioId < 0 || project.DefaultScenarioId >= project.Scenarios.Count)
            throw ProsperoErrorInfo.Unsupported("Unsupported debug/nwonly PlayGo project counts or default scenario.");
        RequireAscii(contentId, 128, "content ID");
        for (int i = 0; i < project.Chunks.Count; i++)
        {
            if (project.Chunks[i].Id != i) throw new InvalidDataException("PlayGo chunk IDs must be contiguous from zero.");
            RequireAscii(project.Chunks[i].Label, int.MaxValue, "chunk label");
        }
        for (int i = 0; i < project.Scenarios.Count; i++)
        {
            PlayGoScenario scenario = project.Scenarios[i];
            if (scenario.Id != i || scenario.Chunks.Count == 0 || scenario.InitialChunkCount < 0 || scenario.InitialChunkCount > scenario.Chunks.Count ||
                scenario.Chunks.Any(c => c < 0 || c >= project.Chunks.Count) || scenario.Chunks.Distinct().Count() != scenario.Chunks.Count)
                throw new InvalidDataException("Invalid debug/nwonly PlayGo scenario.");
            RequireAscii(scenario.Label, int.MaxValue, "scenario label");
        }
    }

    private static void WriteHeader(byte[] data, string contentId, PlayGoProject project, int d0, int d8, int e0, int e8,
        int f0, int f8, int c8Size, int chunkLabelSize, int d8Size, int e8Size, int scenarioLabelSize)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 0x1000);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0xa), (ushort)project.Chunks.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0xe), (ushort)project.Scenarios.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), (uint)data.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x14), (ushort)project.DefaultScenarioId);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x16), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x1c), DebugHeaderFlags);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x20), DebugHeaderUse);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x24), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x30), DebugHeaderUnknown);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x38), ulong.MaxValue);
        Encoding.ASCII.GetBytes(contentId).CopyTo(data.AsSpan(0x40));
        WriteSection(data, 0xc0, HeaderSize, project.Chunks.Count * RecordSize);
        WriteSection(data, 0xc8, HeaderSize + project.Chunks.Count * RecordSize, c8Size);
        WriteSection(data, 0xd0, d0, chunkLabelSize);
        WriteSection(data, 0xd8, d8, d8Size);
        WriteSection(data, 0xe0, e0, project.Scenarios.Count * RecordSize);
        WriteSection(data, 0xe8, e8, e8Size);
        WriteSection(data, 0xf0, f0, scenarioLabelSize);
        WriteSection(data, 0xf8, f8, 0);
    }

    private static void WriteSection(byte[] data, int offset, int start, int size)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), (uint)start);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset + 4), (uint)size);
    }

    private static byte[] EncodeLabels(IEnumerable<string> labels) => Encoding.ASCII.GetBytes(string.Concat(labels.Select(l => l + '\0')));
    private static int LabelOffset<T>(IReadOnlyList<T> values, int index) where T : notnull => values.Take(index).Sum(v => Encoding.ASCII.GetByteCount(v switch { PlayGoChunk c => c.Label, PlayGoScenario s => s.Label, _ => throw new InvalidOperationException() }) + 1);
    private static void RequireAscii(string value, int maxLength, string name)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maxLength || value.Any(c => c is < ' ' or > '~'))
            throw new InvalidDataException($"PlayGo {name} must be non-empty printable ASCII.");
    }
    private readonly record struct PhysicalLeaf(long OnDiskOffset, long OnDiskSize, byte ChunkId);
}
