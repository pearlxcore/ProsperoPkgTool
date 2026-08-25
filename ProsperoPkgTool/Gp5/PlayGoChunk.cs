using System.Buffers.Binary;
using System.Text;

namespace ProsperoPkgTool.Gp5;

public sealed record PlayGoChunk(int Id, string Label, ulong LanguageMask);

public sealed record PlayGoScenario(
    int Id,
    string Label,
    int InitialChunkCount,
    IReadOnlyList<int> Chunks);

public sealed class PlayGoProject
{
    public ushort VersionMajor { get; init; }
    public ushort VersionMinor { get; init; }
    public string ContentId { get; init; } = string.Empty;
    public int DefaultScenarioId { get; init; }
    public IReadOnlyList<PlayGoChunk> Chunks { get; init; } = [];
    public IReadOnlyList<PlayGoScenario> Scenarios { get; init; } = [];
}

public static class PlayGoChunkReader
{
    private const uint PlgxMagic = 0x78676C70;
    private const int HeaderSize = 0x100;
    private const int AttributeSize = 0x20;

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
        Section chunkLabels = ReadSection(data, 0xD0, "chunk labels");
        Section scenarioAttrs = ReadSection(data, 0xE0, "scenario attributes");
        Section scenarioChunks = ReadSection(data, 0xE8, "scenario chunks");
        Section scenarioLabels = ReadSection(data, 0xF0, "scenario labels");
        RequireCapacity(chunkAttrs, chunkCount, AttributeSize, "chunk attributes");
        RequireCapacity(scenarioAttrs, scenarioCount, AttributeSize, "scenario attributes");

        var chunks = new List<PlayGoChunk>(chunkCount);
        for (int index = 0; index < chunkCount; index++)
        {
            int at = checked(chunkAttrs.Offset + index * AttributeSize);
            ulong languageMask = U64(data, at + 0x10);
            uint labelOffset = U32(data, at + 0x1C);
            string label = ReadLabel(data, chunkLabels, labelOffset, $"chunk {index}");
            chunks.Add(new PlayGoChunk(index, label, languageMask));
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
            Chunks = chunks,
            Scenarios = scenarios,
        };
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

