using System.Buffers.Binary;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validation of the clean-room stored-PFSC writer/reader pair
/// (<see cref="ProsperoPfscWriter"/>/<see cref="ProsperoPfscReader"/>) — the first
/// layer of the <c>img_create</c> inverse pipeline. Confirms the exact little-endian
/// header layout, the fixed 0x400 pointer table with its trailing sentinel entry, and
/// byte-exact round-tripping across block-boundary cases.
/// </summary>
public sealed class ProsperoPfscWriterTests
{
    private const int BlockSize = ProsperoPfscWriter.BlockSize; // 0x10000

    [Fact]
    public void Header_Fields_HaveExactLayout()
    {
        byte[] payload = new byte[1];
        byte[] container = ProsperoPfscWriter.Write(payload);

        Assert.Equal((uint)0x43534650, BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(0x00))); // magic 'PFSC'
        Assert.Equal(0, BinaryPrimitives.ReadInt32LittleEndian(container.AsSpan(0x04)));                  // unk4
        Assert.Equal(6, BinaryPrimitives.ReadInt32LittleEndian(container.AsSpan(0x08)));                  // unk8
        Assert.Equal(BlockSize, BinaryPrimitives.ReadInt32LittleEndian(container.AsSpan(0x0C))); // block size (4)
        Assert.Equal(BlockSize, BinaryPrimitives.ReadInt64LittleEndian(container.AsSpan(0x10))); // block size (8)
        Assert.Equal(0x400L, BinaryPrimitives.ReadInt64LittleEndian(container.AsSpan(0x18)));    // pointer table offset
        Assert.Equal(0x10000L, (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(0x20))); // data start
        Assert.Equal(BlockSize, BinaryPrimitives.ReadInt64LittleEndian(container.AsSpan(0x28))); // data length
    }

    [Fact]
    public void PointerTable_HasSentinelEndEntry()
    {
        byte[] payload = new byte[BlockSize]; // exactly one block
        byte[] container = ProsperoPfscWriter.Write(payload);

        // One block -> two pointer entries: block[0] and the sentinel "end" offset.
        Assert.Equal(0x10000L, BinaryPrimitives.ReadInt64LittleEndian(container.AsSpan(0x400)));
        Assert.Equal(0x20000L, BinaryPrimitives.ReadInt64LittleEndian(container.AsSpan(0x408)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(BlockSize - 1)]
    [InlineData(BlockSize)]
    [InlineData(BlockSize + 1)]
    [InlineData(3 * BlockSize - 5)]
    public void RoundTrip_PreservesPayload(int size)
    {
        var payload = new byte[size];
        for (int i = 0; i < size; i++)
            payload[i] = (byte)(i * 31 + 7);

        byte[] container = ProsperoPfscWriter.Write(payload);
        byte[] decoded = ProsperoPfscReader.Read(container);

        // The stored format does not record the logical payload length — the data region
        // is always a whole number of blocks (zero-padded). The payload is therefore a
        // prefix of the reconstructed block-aligned data.
        long expectedLength = ProsperoPfscWriter.ComputeBlockCount(size) * BlockSize;
        Assert.Equal(expectedLength, decoded.Length);
        Assert.Equal(payload, decoded.AsSpan(0, payload.Length).ToArray());
    }

    [Fact]
    public void BlockCount_MatchesCeil()
    {
        Assert.Equal(0, ProsperoPfscWriter.ComputeBlockCount(0));
        Assert.Equal(1, ProsperoPfscWriter.ComputeBlockCount(1));
        Assert.Equal(1, ProsperoPfscWriter.ComputeBlockCount(BlockSize));
        Assert.Equal(2, ProsperoPfscWriter.ComputeBlockCount(BlockSize + 1));
    }

    [Fact]
    public void LargePayload_ExtendsHeaderForPointerTableOverflow()
    {
        // The pointer table overflows the first header block when numBlocks is large enough
        // that (numBlocks + 1) * 8 > 0xFC00, i.e. numBlocks > ~8064. Force a header extension.
        long numBlocks = 9000;
        long payloadSize = numBlocks * BlockSize;

        // Compute header size directly (not the full container, to avoid a large allocation).
        long headerSize = ProsperoPfscWriter.ComputeHeaderSize(payloadSize);
        Assert.True(headerSize > BlockSize, "Expected the header to extend beyond one block.");

        // The pointer table size is (numBlocks + 1) * 8; it must fit within headerSize - 0x400.
        long tableBytes = (numBlocks + 1) * 8;
        Assert.True(ProsperoPfscWriter.PointerTableOffset + tableBytes <= headerSize);
    }

    [Fact]
    public void Compressed_CompressibleData_RoundTrips()
    {
        // Highly compressible payload spanning several blocks.
        var payload = new byte[4 * BlockSize];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i / 16);

        byte[] container = ProsperoPfscWriter.WriteCompressed(payload);
        byte[] decoded = ProsperoPfscReader.Read(container);

        Assert.Equal(payload, decoded);
    }

    [Fact]
    public void Compressed_CompressibleData_IsSmaller()
    {
        var payload = new byte[4 * BlockSize];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = 0xAB;

        byte[] compressed = ProsperoPfscWriter.WriteCompressed(payload);
        byte[] stored = ProsperoPfscWriter.Write(payload);

        Assert.True(compressed.Length < stored.Length,
            $"Expected compressed ({compressed.Length}) to be smaller than stored ({stored.Length}).");
    }

    [Fact]
    public void Compressed_IncompressibleData_FallsBackToRaw()
    {
        // Random data does not compress; the writer should fall back to a stored container.
        var payload = new byte[BlockSize];
        new Random(1234).NextBytes(payload);

        byte[] compressed = ProsperoPfscWriter.WriteCompressed(payload);
        byte[] stored = ProsperoPfscWriter.Write(payload);

        Assert.Equal(stored, compressed);
    }

    [Fact]
    public void Compressed_SmallPayload_StillRoundTrips()
    {
        var payload = new byte[100];
        new Random(7).NextBytes(payload);

        byte[] container = ProsperoPfscWriter.WriteCompressed(payload);
        byte[] decoded = ProsperoPfscReader.Read(container);

        // Data length is block-aligned; the logical payload is a prefix.
        Assert.Equal(payload, decoded.AsSpan(0, payload.Length).ToArray());
    }
}
