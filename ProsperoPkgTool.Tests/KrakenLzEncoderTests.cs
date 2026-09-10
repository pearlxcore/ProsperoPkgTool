using System.Buffers.Binary;
using ProsperoPkgTool.Compression;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class KrakenLzEncoderTests
{
    [Theory]
    [InlineData(0x1000)]
    [InlineData(0x20000)]
    [InlineData(0x30000)]
    [InlineData(0x40000)]
    public void ZeroRuns_RoundTripThroughExistingDecoder(int size)
    {
        byte[] input = new byte[size];
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncodeNewLz(input));

        Assert.Equal(KrakenEncoder.LiteralMode.NewLz, encoded.Mode);
        Assert.Equal(size > 0x20000 ? 0x22 : 0x02, encoded.Flags);
        Assert.True(encoded.Payload.Length < 64);

        byte[] output = new byte[size];
        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
    }

    [Fact]
    public void MetadataLikeInput_CompressesDramatically()
    {
        byte[] input = BuildMetadataLike(0x40000);
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncodeNewLz(input));

        Assert.True(encoded.Payload.Length < input.Length / 8,
            $"expected strong compression, got {encoded.Payload.Length}/{input.Length}");
        RoundTrip(input, encoded);
    }

    [Fact]
    public void LongLiteralRunAndLongMatch_UseEscapedLengths()
    {
        // ~900 non-repeating bytes (a literal run well past the 257 direct-escape limit) followed by
        // a long zero run (a match past the 271 direct-escape limit) exercises both 255 escapes and
        // the forward/backward excess length region.
        var input = new byte[0x20000];
        var rng = new Random(99);
        for (int i = 0; i < 900; i++)
        {
            byte v = (byte)rng.Next(1, 255);
            if (i > 0 && v == input[i - 1]) v ^= 0x5A;
            input[i] = v;
        }
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncodeNewLz(input));
        // The ~900 literal bytes remain raw; everything from 901 onward collapses to one match.
        Assert.True(encoded.Payload.Length < 1024, $"got {encoded.Payload.Length}");
        RoundTrip(input, encoded);
    }

    [Fact]
    public void IncompressibleInput_Declines()
    {
        byte[] random = new byte[0x20000];
        new Random(7).NextBytes(random);
        Assert.Null(KrakenEncoder.TryEncodeNewLz(random));
        Assert.Null(KrakenEncoder.TryEncodeNewLz([]));
    }

    [Fact]
    public void Output_IsDeterministic()
    {
        byte[] input = BuildMetadataLike(0x40000);
        KrakenEncoder.EncodedBlock a = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncodeNewLz(input));
        KrakenEncoder.EncodedBlock b = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncodeNewLz(input));
        Assert.Equal(a.Payload, b.Payload);
        Assert.Equal(a.Flags, b.Flags);
        Assert.Equal(a.FirstChunkCompressedLength, b.FirstChunkCompressedLength);
    }

    [Fact]
    public void CompressedContainer_RoundTripsBlockByBlock()
    {
        byte[] payload = BuildMetadataLike(5 * 0x40000 / 2);
        (byte[] container, IReadOnlyList<ProsperoPfsv3Writer.CompressedBlock> blocks) =
            ProsperoPfsv3Writer.WriteCompressed(payload);

        Assert.Contains(blocks, b => b.Flags != 0);
        Assert.True(container.Length < payload.Length / 4);
        Assert.Equal(payload, DecodeContainer(container));
    }

    [Fact]
    public void CompressedContainer_StoresIncompressibleBlocks()
    {
        byte[] payload = new byte[0x20000];
        new Random(11).NextBytes(payload);
        (byte[] container, IReadOnlyList<ProsperoPfsv3Writer.CompressedBlock> blocks) =
            ProsperoPfsv3Writer.WriteCompressed(payload);

        Assert.All(blocks, b => Assert.Equal(0, b.Flags));
        Assert.Equal(payload, DecodeContainer(container));
    }

    private static void RoundTrip(byte[] input, KrakenEncoder.EncodedBlock encoded)
    {
        byte[] output = new byte[input.Length];
        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
    }

    /// <summary>
    /// Builds a metadata-like buffer: sparse structure in the first part and long zero runs elsewhere,
    /// including a straight non-repeating region long enough to need an escaped literal length.
    /// </summary>
    private static byte[] BuildMetadataLike(int size)
    {
        var buffer = new byte[size];
        var rng = new Random(2024);
        int limit = Math.Min(size, 0x8000);
        for (int i = 0; i < limit; i += 0xA8)
        {
            buffer[i] = (byte)(i & 0xFF);
            if (i + 4 < limit) BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(i + 4), (uint)i);
            if (i + 16 < limit) BinaryPrimitives.WriteInt64LittleEndian(buffer.AsSpan(i + 8), i);
        }
        for (int i = 0; i < 900 && i + 0x10000 < size; i++)
        {
            byte v = (byte)rng.Next(1, 255);
            if (i > 0 && v == buffer[0x10000 + i - 1]) v ^= 0x5A;
            buffer[0x10000 + i] = v;
        }
        return buffer;
    }

    private static byte[] DecodeContainer(byte[] container)
    {
        int blockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(8));
        long uncompressedSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(24));
        (int off3, int size3) = Section(container, 3);
        (int off7, _) = Section(container, 7);
        int blockCount = size3 / 16 - 1;

        var output = new byte[uncompressedSize];
        for (int i = 0; i < blockCount; i++)
        {
            int e = off3 + i * 16;
            ulong e0 = BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(e));
            ulong e1 = BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(e + 8));
            ulong next0 = BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(e + 16));
            ulong next1 = BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(e + 24));
            long compressedOffset = (long)(e0 & 0xFFFFFFFFFFFL);
            int compressedSize = (int)((long)(next0 & 0xFFFFFFFFFFFL) - compressedOffset);
            long uncompressedOffset = (long)(e1 & 0xFFFFFFFFFFFL);
            int uncompressedLength = (int)((long)(next1 & 0xFFFFFFFFFFFL) - uncompressedOffset);
            int sizeHint = (int)((e1 >> 44) & 0x1FFFF);
            int flags = (int)((e0 >> 48) & 0xFF);

            ReadOnlySpan<byte> block = container.AsSpan(off7 + (int)compressedOffset, compressedSize);
            Span<byte> destination = output.AsSpan((int)uncompressedOffset, uncompressedLength);
            if (compressedSize == uncompressedLength)
            {
                block.CopyTo(destination);
                continue;
            }
            bool multi = uncompressedLength > KrakenDecoder.ChunkSize;
            int firstChunk = multi ? sizeHint + 1 : 0;
            KrakenDecoder.KrakenDecodeStatus status = KrakenDecoder.DecodeBlock(block, flags, firstChunk, destination);
            Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success, status);
        }
        return output;
    }

    private static (int Offset, int Size) Section(byte[] container, int id)
    {
        for (int i = 0; i < 7; i++)
        {
            int p = 0x48 + i * 16;
            if (BinaryPrimitives.ReadUInt16LittleEndian(container.AsSpan(p)) == id)
                return ((int)BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(p + 2)),
                        (int)BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(p + 10)));
        }
        return (0, 0);
    }
}
