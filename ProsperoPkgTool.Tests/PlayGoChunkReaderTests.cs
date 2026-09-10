using System.Buffers.Binary;
using System.Text;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class PlayGoChunkReaderTests
{
    [Fact]
    public void ReadsTwoChunkTwoScenarioOracleArtifact()
    {
        // Captured from a controlled, locally generated original-tool package: two chunks,
        // two playmode scenarios, scenario 1 sequence [0, 1]. It is evidence for reader
        // interoperability only; it does not authorize a PLGX writer.
        byte[] data = Convert.FromBase64String(
            "cGxneAAQAAABAAIAAAACAAACAAAAAAEAAAAAAAAAhQACAAAAAQAAAAAAAAAAAAAAEQAAAAAAAAD//////////0lWOTk5OS1QUFNYNDAwMDBfMDAtWFhYWFhYWFhYWFhYWFhYWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAEAAAABAAQAACAAAAFABAAASAAAAcAEAACAAAACQAQAAQAAAANABAAAGAAAA4AEAABgAAAAAAAAAAAAAAIAAAwACAAAAEQAAAAAAAAD//////////wAAAAAAAAAAgAADAAAAAAARAAAAAAAAAP//////////CAAAAAkAAAAAAAAAAQAAAAAAAAAAAAAAQ2h1bmsgIzAAQ2h1bmsgIzEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAcAAAAAACEAAAAAAAAAAAAAAAAAAAAAAAAAAQABAAAAAAAAAAAAIQAAAAAAAAAAAAAAAAAAAAAAAAABAAIAAgAAAAwAAAAAAAAAAQAAAAAAAAAAAAAAU2NlbmFyaW8gIzAAU2NlbmFyaW8gIzEAAAAAAAAAAAA=");

        PlayGoProject project = PlayGoChunkReader.Read(data);

        Assert.Equal(["Chunk #0", "Chunk #1"], project.Chunks.Select(chunk => chunk.Label));
        Assert.Equal(2, project.Scenarios.Count);
        Assert.Equal([0], project.Scenarios[0].Chunks);
        Assert.Equal([0, 1], project.Scenarios[1].Chunks);
        Assert.Equal(1, project.Scenarios[1].InitialChunkCount);
    }

    [Fact]
    public void ReadsRealScenarioSequenceInsteadOfAssigningAllChunks()
    {
        byte[] data = BuildTwoChunkFile();
        PlayGoProject project = PlayGoChunkReader.Read(data);

        Assert.Equal(2, project.Chunks.Count);
        Assert.Equal("A", project.Chunks[0].Label);
        Assert.Equal("B", project.Chunks[1].Label);
        PlayGoScenario scenario = Assert.Single(project.Scenarios);
        Assert.Equal([1, 0], scenario.Chunks);
        Assert.Equal(1, scenario.InitialChunkCount);
    }

    [Fact]
    public void RejectsOutOfBoundsLabelAndSequenceOffsets()
    {
        byte[] badLabel = BuildTwoChunkFile();
        WriteU32(badLabel, 0x100 + 0x1C, 99);
        Assert.Throws<InvalidDataException>(() => PlayGoChunkReader.Read(badLabel));

        byte[] badSequence = BuildTwoChunkFile();
        WriteU32(badSequence, 0x160 + 0x18, 99);
        Assert.Throws<InvalidDataException>(() => PlayGoChunkReader.Read(badSequence));
    }

    private static byte[] BuildTwoChunkFile()
    {
        byte[] data = new byte[0x1A0];
        Encoding.ASCII.GetBytes("plgx").CopyTo(data, 0);
        WriteU16(data, 0x04, 0x1000);
        WriteU16(data, 0x08, 1);
        WriteU16(data, 0x0A, 2);
        WriteU16(data, 0x0E, 1);
        WriteU32(data, 0x10, (uint)data.Length);
        Encoding.ASCII.GetBytes("UP0000-PPSA12345_00-TESTPACKAGE00000").CopyTo(data, 0x40);
        WriteSection(data, 0xC0, 0x100, 0x40);
        WriteSection(data, 0xC8, 0x140, 0);
        WriteSection(data, 0xD0, 0x140, 4);
        WriteSection(data, 0xD8, 0x150, 0);
        WriteSection(data, 0xE0, 0x160, 0x20);
        WriteSection(data, 0xE8, 0x180, 4);
        WriteSection(data, 0xF0, 0x190, 2);
        WriteSection(data, 0xF8, 0x1A0, 0);

        WriteU64(data, 0x110, ulong.MaxValue);
        WriteU32(data, 0x11C, 0);
        WriteU64(data, 0x130, 1);
        WriteU32(data, 0x13C, 2);
        data[0x140] = (byte)'A'; data[0x141] = 0;
        data[0x142] = (byte)'B'; data[0x143] = 0;

        WriteU16(data, 0x160 + 0x14, 1);
        WriteU16(data, 0x160 + 0x16, 2);
        WriteU32(data, 0x160 + 0x18, 0);
        WriteU32(data, 0x160 + 0x1C, 0);
        WriteU16(data, 0x180, 1);
        WriteU16(data, 0x182, 0);
        data[0x190] = (byte)'S'; data[0x191] = 0;
        return data;
    }

    private static void WriteSection(byte[] data, int at, uint offset, uint size)
    {
        WriteU32(data, at, offset);
        WriteU32(data, at + 4, size);
    }

    private static void WriteU16(byte[] data, int at, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(at, 2), value);

    private static void WriteU32(byte[] data, int at, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at, 4), value);

    private static void WriteU64(byte[] data, int at, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(at, 8), value);
}
