using System.Buffers.Binary;
using System.Text;

namespace ProsperoPkgTool.Gp5;

public sealed record PlayGoChunk(int Id, string Label, ulong LanguageMask);

public sealed record PlayGoScenario(
    int Id,
    string Label,
    int InitialChunkCount,
    IReadOnlyList<int> Chunks);

/// <summary>One ownership extent declared by a PlayGo chunk: a 64-KiB-aligned <c>[Start, Start+Length)</c> range.</summary>
public sealed record PlayGoExtent(int ChunkId, ulong Start, ulong Length);

/// <summary>
/// One per-file PlayGo assignment from the hash table + FICM pair. <see cref="Path"/> is the
/// normalized inner-image relative path when the caller supplied a hash-to-path map, else null.
/// </summary>
public sealed record PlayGoAssignment(ulong PathHash, int ChunkId, string? Path);

public sealed class PlayGoProject
{
    public ushort VersionMajor { get; init; }
    public ushort VersionMinor { get; init; }
    public string ContentId { get; init; } = string.Empty;
    public int DefaultScenarioId { get; init; }

    /// <summary>Header flags word at 0x1C. Treated as opaque: debug/nwonly output uses 0x85.</summary>
    public uint HeaderFlags { get; init; }

    public IReadOnlyList<PlayGoChunk> Chunks { get; init; } = [];
    public IReadOnlyList<PlayGoScenario> Scenarios { get; init; } = [];

    /// <summary>Chunk ownership extents in chunk/record order (the 0xC8 extent-id lists into 0xD8).</summary>
    public IReadOnlyList<PlayGoExtent> Extents { get; init; } = [];

    /// <summary>Per-file chunk assignments from the hash table + FICM, when supplied to <see cref="PlayGoChunkReader"/>.</summary>
    public IReadOnlyList<PlayGoAssignment> Assignments { get; init; } = [];

    /// <summary>
    /// Explicit clean-room mapping of normalized inner-PFS file paths to chunk IDs. Entries not
    /// present here use chunk zero in the debug/nwonly source-folder model.
    /// </summary>
    public IReadOnlyDictionary<string, byte> FileChunkAssignments { get; init; } =
        new Dictionary<string, byte>(StringComparer.Ordinal);
}

public static class PlayGoChunkReader
{
    private const uint PlgxMagic = 0x78676C70;
    private const int HeaderSize = 0x100;
    private const int AttributeSize = 0x20;
    private const int ExtentSize = 0x10;
    private const int HashTableHeaderSize = 0x38;
    private const int HashTableCountOffset = 0x24;
    private const int FicmHeaderSize = 0x10;

    public static PlayGoProject Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Read(File.ReadAllBytes(path));
    }

    public static PlayGoProject Read(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new InvalidDataException("playgo-chunk.dat is shorter than its 0x100-byte header.");
        if (U32(data, 0) != PlgxMagic)
            throw new InvalidDataException("playgo-chunk.dat does not contain PS5 'plgx' magic.");

        ushort versionMajor = U16(data, 0x04);
        ushort versionMinor = U16(data, 0x06);
        int imageCount = U16(data, 0x08);
        int chunkCount = U16(data, 0x0A);
        int scenarioCount = U16(data, 0x0E);
        uint declaredSize = U32(data, 0x10);
        int defaultScenario = U16(data, 0x14);
        uint headerFlags = U32(data, 0x1C);

        if (declaredSize < HeaderSize || declaredSize > data.Length)
            throw new InvalidDataException("playgo-chunk.dat declared file_size is outside the file.");
        data = data[..checked((int)declaredSize)];
        if (imageCount is < 1 or > 2)
            throw new InvalidDataException($"Implausible PlayGo image count {imageCount}.");
        if (chunkCount is < 1 or > 1000)
            throw new InvalidDataException($"Implausible PlayGo chunk count {chunkCount}.");
        if (scenarioCount is < 1 or > 32)
            throw new InvalidDataException($"Implausible PlayGo scenario count {scenarioCount}.");
        if (defaultScenario >= scenarioCount)
            throw new InvalidDataException("PlayGo default scenario ID is outside the scenario table.");

        Section chunkAttrs = ReadSection(data, 0xC0, "chunk attributes");
        Section chunkExtentIds = ReadSection(data, 0xC8, "chunk extent ids");
        Section chunkLabels = ReadSection(data, 0xD0, "chunk labels");
        Section extents = ReadSection(data, 0xD8, "extents");
        Section scenarioAttrs = ReadSection(data, 0xE0, "scenario attributes");
        Section scenarioChunks = ReadSection(data, 0xE8, "scenario chunks");
        Section scenarioLabels = ReadSection(data, 0xF0, "scenario labels");
        RequireCapacity(chunkAttrs, chunkCount, AttributeSize, "chunk attributes");
        RequireCapacity(scenarioAttrs, scenarioCount, AttributeSize, "scenario attributes");
        if (extents.Size % ExtentSize != 0)
            throw new InvalidDataException("PlayGo extent section is not a multiple of 16 bytes.");
        if (chunkExtentIds.Size % sizeof(uint) != 0)
            throw new InvalidDataException("PlayGo chunk extent-id list is not a multiple of 4 bytes.");
        int extentCount = extents.Size / ExtentSize;

        var chunks = new List<PlayGoChunk>(chunkCount);
        var projectExtents = new List<PlayGoExtent>();
        for (int index = 0; index < chunkCount; index++)
        {
            int at = checked(chunkAttrs.Offset + index * AttributeSize);
            ulong languageMask = U64(data, at + 0x10);
            uint labelOffset = U32(data, at + 0x1C);
            string label = ReadLabel(data, chunkLabels, labelOffset, $"chunk {index}");
            chunks.Add(new PlayGoChunk(index, label, languageMask));

            int extentIdCount = checked((int)U32(data, at + 0x04));
            int extentListOffset = checked((int)U32(data, at + 0x18));
            if (extentIdCount < 0 || extentListOffset < 0 ||
                (long)extentListOffset + (long)extentIdCount * sizeof(uint) > chunkExtentIds.Size)
            {
                throw new InvalidDataException($"PlayGo chunk {index} extent-id list is outside its section.");
            }
            for (int extent = 0; extent < extentIdCount; extent++)
            {
                int id = checked((int)U32(data, checked(chunkExtentIds.Offset + extentListOffset + extent * sizeof(uint))));
                if (id < 0 || id >= extentCount)
                    throw new InvalidDataException($"PlayGo chunk {index} references undefined extent {id}.");
                int extentAt = checked(extents.Offset + id * ExtentSize);
                projectExtents.Add(new PlayGoExtent(index, U64(data, extentAt), U64(data, extentAt + 8)));
            }
        }

        var scenarios = new List<PlayGoScenario>(scenarioCount);
        for (int index = 0; index < scenarioCount; index++)
        {
            int at = checked(scenarioAttrs.Offset + index * AttributeSize);
            int initialCount = U16(data, at + 0x14);
            int sequenceCount = U16(data, at + 0x16);
            uint sequenceOffset = U32(data, at + 0x18);
            uint labelOffset = U32(data, at + 0x1C);
            if (initialCount > sequenceCount)
                throw new InvalidDataException($"PlayGo scenario {index} initial chunk count exceeds its sequence.");
            if ((sequenceOffset & 1) != 0 || sequenceOffset > scenarioChunks.Size ||
                (long)sequenceOffset + sequenceCount * 2L > scenarioChunks.Size)
                throw new InvalidDataException($"PlayGo scenario {index} chunk sequence is outside its section.");

            var sequence = new List<int>(sequenceCount);
            var seen = new HashSet<int>();
            for (int sequenceIndex = 0; sequenceIndex < sequenceCount; sequenceIndex++)
            {
                int chunk = U16(data, checked(scenarioChunks.Offset + (int)sequenceOffset + sequenceIndex * 2));
                if (chunk >= chunkCount)
                    throw new InvalidDataException($"PlayGo scenario {index} references undefined chunk {chunk}.");
                if (!seen.Add(chunk))
                    throw new InvalidDataException($"PlayGo scenario {index} contains duplicate chunk {chunk}.");
                sequence.Add(chunk);
            }
            if (sequence.Count == 0)
                throw new InvalidDataException($"PlayGo scenario {index} has an empty chunk sequence.");
            string label = ReadLabel(data, scenarioLabels, labelOffset, $"scenario {index}");
            scenarios.Add(new PlayGoScenario(index, label, initialCount, sequence));
        }

        return new PlayGoProject
        {
            VersionMajor = versionMajor,
            VersionMinor = versionMinor,
            ContentId = ReadFixedAscii(data.Slice(0x40, 128)),
            DefaultScenarioId = defaultScenario,
            HeaderFlags = headerFlags,
            Chunks = chunks,
            Scenarios = scenarios,
            Extents = projectExtents,
        };
    }

    /// <summary>
    /// Reads a PLGX descriptor plus its <c>playgo-hash-table.dat</c> and <c>playgo-ficm.dat</c>
    /// companions, attaching the resolved per-file chunk assignments.
    /// </summary>
    public static PlayGoProject Read(ReadOnlySpan<byte> data, ReadOnlySpan<byte> hashTable, ReadOnlySpan<byte> ficm,
        IReadOnlyDictionary<ulong, string>? pathByHash = null)
    {
        PlayGoProject project = Read(data);
        IReadOnlyList<PlayGoAssignment> assignments = ReadAssignments(hashTable, ficm, pathByHash);
        return new PlayGoProject
        {
            VersionMajor = project.VersionMajor,
            VersionMinor = project.VersionMinor,
            ContentId = project.ContentId,
            DefaultScenarioId = project.DefaultScenarioId,
            HeaderFlags = project.HeaderFlags,
            Chunks = project.Chunks,
            Scenarios = project.Scenarios,
            Extents = project.Extents,
            Assignments = assignments,
            FileChunkAssignments = project.FileChunkAssignments,
        };
    }

    /// <summary>
    /// Resolves the per-file chunk ids from the 0x38 hash table and the FICM, optionally mapping
    /// each 64-bit path hash to a path. The hash is the inner-image relative path (no leading
    /// slash) through <see cref="Containers.ProsperoOuterPfsBuilder.FltPathHash"/>.
    /// </summary>
    public static IReadOnlyList<PlayGoAssignment> ReadAssignments(ReadOnlySpan<byte> hashTable,
        ReadOnlySpan<byte> ficm, IReadOnlyDictionary<ulong, string>? pathByHash = null)
    {
        if (hashTable.Length < HashTableHeaderSize)
            throw new InvalidDataException("playgo-hash-table.dat is shorter than its 0x38-byte header.");
        int count = checked((int)U32(hashTable, HashTableCountOffset));
        if (count < 0 || (long)HashTableHeaderSize + (long)count * sizeof(ulong) > hashTable.Length)
            throw new InvalidDataException("PlayGo hash table is shorter than its declared count.");

        if (ficm.Length < FicmHeaderSize)
            throw new InvalidDataException("playgo-ficm.dat is shorter than its 0x10-byte header.");
        // The FICM carries a byte length at 0x0C (count * 2); when present it must agree with the
        // hash-table count. Fall back to the hash-table count when it is absent.
        uint declared = U32(ficm, 0x0C);
        if (declared != 0 && (declared % sizeof(ushort) != 0 || declared / sizeof(ushort) != (uint)count))
            throw new InvalidDataException("PlayGo FICM count disagrees with the hash table.");
        if ((long)FicmHeaderSize + (long)count * sizeof(ushort) > ficm.Length)
            throw new InvalidDataException("PlayGo FICM is shorter than the hash-table count.");

        var assignments = new List<PlayGoAssignment>(count);
        for (int i = 0; i < count; i++)
        {
            ulong hash = U64(hashTable, HashTableHeaderSize + i * sizeof(ulong));
            int chunk = U16(ficm, FicmHeaderSize + i * sizeof(ushort));
            string? path = pathByHash is not null && pathByHash.TryGetValue(hash, out string? resolved)
                ? resolved : null;
            assignments.Add(new PlayGoAssignment(hash, chunk, path));
        }
        return assignments;
    }

    private static Section ReadSection(ReadOnlySpan<byte> data, int pointerOffset, string name)
    {
        uint offset = U32(data, pointerOffset);
        uint size = U32(data, pointerOffset + 4);
        if (offset > data.Length || (long)offset + size > data.Length)
            throw new InvalidDataException($"PlayGo {name} section is outside the file.");
        return new Section(checked((int)offset), checked((int)size));
    }

    private static void RequireCapacity(Section section, int count, int stride, string name)
    {
        if ((long)count * stride > section.Size)
            throw new InvalidDataException($"PlayGo {name} section is shorter than its declared count.");
    }

    private static string ReadLabel(ReadOnlySpan<byte> data, Section section, uint relativeOffset, string owner)
    {
        if (relativeOffset >= section.Size)
            throw new InvalidDataException($"PlayGo {owner} label offset is outside the label section.");
        ReadOnlySpan<byte> remaining = data.Slice(checked(section.Offset + (int)relativeOffset),
            section.Size - checked((int)relativeOffset));
        int terminator = remaining.IndexOf((byte)0);
        if (terminator < 0)
            throw new InvalidDataException($"PlayGo {owner} label is not NUL terminated.");
        if (remaining[..terminator].ContainsAnyExceptInRange((byte)0x20, (byte)0x7E))
            throw new InvalidDataException($"PlayGo {owner} label contains non-ASCII control data.");
        return Encoding.ASCII.GetString(remaining[..terminator]);
    }

    private static string ReadFixedAscii(ReadOnlySpan<byte> value)
    {
        int terminator = value.IndexOf((byte)0);
        if (terminator >= 0)
            value = value[..terminator];
        return Encoding.ASCII.GetString(value).TrimEnd();
    }

    private static ushort U16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));

    private static uint U32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));

    private static ulong U64(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, 8));

    private readonly record struct Section(int Offset, int Size);
}
