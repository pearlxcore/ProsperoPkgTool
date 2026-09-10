using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validation of the clean-room PFSv3 stored-PFSC writer (<see cref="ProsperoPfsv3Writer"/>) —
/// the inner per-file image wrapper. Confirms the exact little-endian header layout, the 7-entry
/// section directory, per-block SHA3-256 hashes, the file-level digest, and byte-exact payload
/// round-tripping across block boundaries.
/// </summary>
public sealed class ProsperoPfsv3WriterTests
{
    private const int BlockSize = ProsperoPfsv3Writer.DefaultBlockSize; // 0x40000

    private static int SectionOffset(ReadOnlySpan<byte> c, int id)
    {
        // Section directory at 0x48, 16-byte entries: {u16 id, u32 offset, 4 reserved, u32 size, 2 reserved}.
        for (int i = 0; i < 7; i++)
        {
            int p = 0x48 + i * 16;
            ushort sid = BinaryPrimitives.ReadUInt16LittleEndian(c[p..]);
            if (sid == id)
                return (int)BinaryPrimitives.ReadUInt32LittleEndian(c[(p + 2)..]);
        }
        return -1;
    }

    [Fact]
    public void Header_Fields_HaveExactLayout()
    {
        byte[] payload = new byte[1];
        byte[] c = ProsperoPfsv3Writer.WriteStored(payload);

        Assert.Equal((uint)0x43534650, BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(0x00))); // 'PFSC'
        Assert.Equal(3, BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(0x04)));                 // version 3
        Assert.Equal(7, BinaryPrimitives.ReadUInt16LittleEndian(c.AsSpan(0x06)));                 // section count
        Assert.Equal(BlockSize, (int)BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(0x08)));    // block size
        Assert.Equal(0x0802u, BinaryPrimitives.ReadUInt32LittleEndian(c.AsSpan(0x0C)));           // encode param 0x0C
        Assert.Equal(1UL, BinaryPrimitives.ReadUInt64LittleEndian(c.AsSpan(0x18)));               // uncompressed size
        Assert.Equal((ulong)c.Length, BinaryPrimitives.ReadUInt64LittleEndian(c.AsSpan(0x20)));   // total size == container length
    }

    [Fact]
    public void Stored_SingleBlock_RoundTripsPayload()
    {
        var payload = new byte[BlockSize / 2];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i * 13 + 1);

        byte[] c = ProsperoPfsv3Writer.WriteStored(payload);
        int dataOffset = SectionOffset(c, 7);
        Assert.True(dataOffset > 0);

        // The payload is stored verbatim at the section-7 data offset.
        Assert.Equal(payload, c.AsSpan(dataOffset, payload.Length).ToArray());
    }

    [Fact]
    public void PerBlockHashes_MatchSha3_256()
    {
        var payload = new byte[BlockSize * 2 + 100];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i * 7 + 3);

        byte[] c = ProsperoPfsv3Writer.WriteStored(payload);
        int hashOffset = SectionOffset(c, 4);
        Assert.True(hashOffset > 0);

        int blockCount = (payload.Length + BlockSize - 1) / BlockSize;
        for (int i = 0; i < blockCount; i++)
        {
            int start = i * BlockSize;
            int len = Math.Min(BlockSize, payload.Length - start);
            byte[] expected = Sha3.Sha3_256(payload.AsSpan(start, len));
            Assert.Equal(expected, c.AsSpan(hashOffset + i * 32, 32).ToArray());
        }
    }

    [Fact]
    public void FileDigest_Verifies()
    {
        var payload = new byte[BlockSize + 123];
        new Random(42).NextBytes(payload);

        byte[] c = ProsperoPfsv3Writer.WriteStored(payload);

        // Recompute the file digest from the parsed metadata and compare to offset 0x28.
        int off2 = SectionOffset(c, 2);
        int off3 = SectionOffset(c, 3);
        int off4 = SectionOffset(c, 4);
        Assert.True(off2 > 0 && off3 > 0 && off4 > 0);

        // header32 = {u32 1, u32 blockSize, u32 param0C, u32 0, u64 param10, u64 uncompressedSize}.
        Span<byte> header32 = stackalloc byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(header32, 1u);
        c.AsSpan(0x08, 8).CopyTo(header32[4..]);   // blockSize + param0C
        c.AsSpan(0x10, 16).CopyTo(header32[16..]); // param10 + uncompressedSize

        int sec2Size = 64;
        int blockCount = (payload.Length + BlockSize - 1) / BlockSize;
        int sec3Size = (blockCount + 1) * 16;
        int sec4Size = blockCount * 32;

        using var ms = new MemoryStream();
        ms.Write(header32);
        ms.Write(c, off2, sec2Size);
        ms.Write(c, off3, sec3Size);
        ms.Write(c, off4, sec4Size);
        byte[] expected = Sha3.Sha3_256(ms.ToArray());

        Assert.Equal(expected, c.AsSpan(0x28, 32).ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(BlockSize - 1)]
    [InlineData(BlockSize)]
    [InlineData(BlockSize + 1)]
    [InlineData(3 * BlockSize - 5)]
    public void RoundTrip_ReconstructsPayload(int size)
    {
        var payload = new byte[size];
        for (int i = 0; i < size; i++)
            payload[i] = (byte)(i * 31 + 7);

        byte[] c = ProsperoPfsv3Writer.WriteStored(payload);
        int dataOffset = SectionOffset(c, 7);
        Assert.True(dataOffset > 0);

        // The stored container places payload bytes contiguously at the data offset.
        Assert.Equal(payload, c.AsSpan(dataOffset, size).ToArray());
    }

    [Fact]
    public void EmptyPayload_ProducesSingleZeroBlock()
    {
        byte[] c = ProsperoPfsv3Writer.WriteStored(Array.Empty<byte>());
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(c.AsSpan(0x18))); // uncompressed size 0
        // Section 3 has 1 block + 1 sentinel = 2 entries.
        int off3 = SectionOffset(c, 3);
        Assert.True(off3 > 0);
        // Sentinel boundary entry equals payload length (0).
        Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(c.AsSpan(off3 + 16)));
    }
}
