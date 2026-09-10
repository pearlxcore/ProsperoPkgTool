using System.Buffers.Binary;
using System.IO.Compression;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room writer for the PS5 "zlib PFSC" image — the outer installable block-indexed
/// image format that wraps a prepared image (the inner <c>pfs_image.dat</c>) as a sequence
/// of fixed-size blocks preceded by a pointer table. This is distinct from the PFSv3 "PFSC"
/// compression container (<see cref="ProsperoPfsv3Writer"/>); the two share the 'PFSC' magic
/// but are disambiguated by the version field at offset 0x04 (this format stores 0 there,
/// while PFSv3 stores 2 or 3).
///
/// Two modes are supported:
///   <see cref="Write"/> — every block stored uncompressed (stored-only).
///   <see cref="WriteCompressed"/> — per-block zlib; a block is stored compressed only when
///       it is smaller than the raw block, otherwise it is stored raw. When no block compresses
///       the payload is returned verbatim (raw fallback).
///
/// On-disk header layout (little-endian; matches the authoritative PFSCHdr):
///   0x00 : magic <c>0x43534650</c> ('PFSC'), 4 bytes (int)
///   0x04 : unk4, 4 bytes (int, always 0)
///   0x08 : unk8, 4 bytes (int, always 6)
///   0x0C : block size, 4 bytes (int, <see cref="BlockSize"/>)
///   0x10 : block size, 8 bytes (long, <see cref="BlockSize"/>)
///   0x18 : block-offsets pointer, 8 bytes (long, always 0x400)
///   0x20 : data start, 8 bytes (ulong, <see cref="ComputeHeaderSize"/>)
///   0x28 : data length, 8 bytes (long, <c>num_blocks * BlockSize</c>)
///   0x400: block-offset table: <c>num_blocks + 1</c> entries of 8 bytes each, where
///          entry[i] = absolute file offset of block i's bytes (the last entry is the
///          sentinel "end" offset).
///   HeaderSize : payload data, where each block is either stored raw (<c>BlockSize</c>
///          bytes) or a zlib stream (2-byte zlib header + DEFLATE + 4-byte Adler32).
///
/// A compressed block is identified by its size in the pointer table differing from
/// <c>BlockSize</c>; readers skip the 2-byte zlib header and inflate the remainder.
/// </summary>
public static class ProsperoPfscWriter
{
    public const int BlockSize = 0x10000;

    /// <summary>Magic 'PFSC' stored little-endian as 0x43534650.</summary>
    public const uint Magic = 0x43534650;

    /// <summary>The value written to the unk8 field (offset 0x08).</summary>
    public const int Unk8 = 6;

    /// <summary>Fixed offset of the block-offset pointer table within the header.</summary>
    public const long PointerTableOffset = 0x400;

    /// <summary>Maximum pointer-table size in bytes that fits the first header block.</summary>
    private const long PointerTableLimit = 0xFC00;

    /// <summary>
    /// Compute the header size (offset of the first data byte) for a payload of
    /// <paramref name="payloadSize"/> bytes.
    /// </summary>
    public static long ComputeHeaderSize(long payloadSize)
    {
        long numBlocks = ComputeBlockCount(payloadSize);
        long pointerTableSize = 8 + numBlocks * 8;
        long additionalPointerBlocks = (pointerTableSize - PointerTableLimit + 0xFFFF) / BlockSize;
        if (additionalPointerBlocks < 0)
            additionalPointerBlocks = 0;
        return BlockSize + additionalPointerBlocks * BlockSize;
    }

    /// <summary>The number of fixed-size blocks a payload of <paramref name="size"/> bytes spans.</summary>
    public static long ComputeBlockCount(long size)
        => (size + BlockSize - 1) / BlockSize;

    /// <summary>
    /// Serialize a stored PFSC container holding <paramref name="payload"/> into
    /// <paramref name="output"/>. The payload is written verbatim (zero-padded to a
    /// whole block) and the block-offset table is emitted with a trailing sentinel entry.
    /// </summary>
    public static void Write(ReadOnlySpan<byte> payload, Stream output)
    {
        ArgumentNullException.ThrowIfNull(output);

        long size = payload.Length;
        long numBlocks = ComputeBlockCount(size);
        long headerSize = ComputeHeaderSize(size);

        WriteHeader(output, headerSize, numBlocks, blockSize32: BlockSize, blockSize64: BlockSize, dataLength: numBlocks * BlockSize);
        WritePointerTable(output, headerSize, numBlocks, _ => BlockSize);

        // Payload data, zero-padded to a whole block.
        output.Write(payload);
        long dataLength = numBlocks * BlockSize;
        WriteZeroes(output, dataLength - size);
    }

    /// <summary>
    /// Convenience: serialize a stored PFSC container for <paramref name="payload"/>
    /// and return the complete container bytes.
    /// </summary>
    public static byte[] Write(ReadOnlySpan<byte> payload)
    {
        using var ms = new MemoryStream(checked((int)(ComputeHeaderSize(payload.Length) + ComputeBlockCount(payload.Length) * BlockSize)));
        Write(payload, ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Serialize a per-block zlib-compressed PFSC container for <paramref name="payload"/>
    /// into <paramref name="output"/>. Each block is compressed with zlib; a block is kept
    /// compressed only when it is smaller than the raw block. When no block compresses, the
    /// payload is written verbatim (raw fallback, identical to <see cref="Write(ReadOnlySpan{byte}, Stream)"/>).
    /// </summary>
    public static void WriteCompressed(ReadOnlySpan<byte> payload, Stream output, CompressionLevel level = CompressionLevel.SmallestSize)
    {
        ArgumentNullException.ThrowIfNull(output);

        long size = payload.Length;
        long numBlocks = ComputeBlockCount(size);

        // Compress each block up-front to decide stored-vs-compressed and total size.
        var blockSizes = new long[numBlocks];
        long compressedBlocks = 0;
        long totalData = 0;
        var blockBuf = new byte[BlockSize];
        for (long i = 0; i < numBlocks; i++)
        {
            int filled = (int)Math.Min(BlockSize, size - i * BlockSize);
            payload.Slice((int)(i * BlockSize), filled).CopyTo(blockBuf);
            if (filled < BlockSize)
                Array.Clear(blockBuf, filled, BlockSize - filled);

            byte[] z = ZlibCompress(blockBuf, level);
            if (z.Length < BlockSize)
            {
                blockSizes[i] = z.Length;
                compressedBlocks++;
            }
            else
            {
                blockSizes[i] = BlockSize;
            }
            totalData += blockSizes[i];
        }

        // Raw fallback: nothing compressed, so emit a plain stored container.
        if (compressedBlocks == 0)
        {
            Write(payload, output);
            return;
        }

        long headerSize = ComputeHeaderSize(size);
        WriteHeader(output, headerSize, numBlocks, blockSize32: BlockSize, blockSize64: BlockSize, dataLength: numBlocks * BlockSize);

        // Pointer table: cumulative offsets over the variable-size blocks.
        WritePointerTable(output, headerSize, numBlocks, i => blockSizes[i]);

        // Block data: stored raw or zlib-compressed.
        for (long i = 0; i < numBlocks; i++)
        {
            int filled = (int)Math.Min(BlockSize, size - i * BlockSize);
            payload.Slice((int)(i * BlockSize), filled).CopyTo(blockBuf);
            if (filled < BlockSize)
                Array.Clear(blockBuf, filled, BlockSize - filled);

            if (blockSizes[i] < BlockSize)
            {
                byte[] z = ZlibCompress(blockBuf, level);
                output.Write(z);
            }
            else
            {
                output.Write(blockBuf);
            }
        }
    }

    /// <summary>
    /// Convenience: serialize a zlib-compressed PFSC container for <paramref name="payload"/>
    /// and return the complete container bytes.
    /// </summary>
    public static byte[] WriteCompressed(ReadOnlySpan<byte> payload, CompressionLevel level = CompressionLevel.SmallestSize)
    {
        using var ms = new MemoryStream();
        WriteCompressed(payload, ms, level);
        return ms.ToArray();
    }

    private static void WriteHeader(Stream output, long headerSize, long numBlocks, int blockSize32, long blockSize64, long dataLength)
    {
        Span<byte> header = stackalloc byte[0x30];
        header.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(header[0x00..], Magic);
        // 0x04 unk4 (int) stays zero.
        BinaryPrimitives.WriteInt32LittleEndian(header[0x08..], Unk8);
        BinaryPrimitives.WriteInt32LittleEndian(header[0x0C..], blockSize32);
        BinaryPrimitives.WriteInt64LittleEndian(header[0x10..], blockSize64);
        BinaryPrimitives.WriteInt64LittleEndian(header[0x18..], PointerTableOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header[0x20..], (ulong)headerSize);
        BinaryPrimitives.WriteInt64LittleEndian(header[0x28..], dataLength);
        output.Write(header);

        // Zero-fill from 0x30 up to the pointer table (0x400).
        WriteZeroes(output, PointerTableOffset - 0x30);
    }

    private static void WritePointerTable(Stream output, long headerSize, long numBlocks, Func<long, long> blockSizeAt)
    {
        var entry = new byte[8];
        long offset = headerSize;
        for (long i = 0; i <= numBlocks; i++)
        {
            BinaryPrimitives.WriteInt64LittleEndian(entry, offset);
            output.Write(entry);
            if (i < numBlocks)
                offset += blockSizeAt(i);
        }

        // Zero-fill from the end of the pointer table to the data start (headerSize).
        long tableEnd = PointerTableOffset + (numBlocks + 1) * 8;
        WriteZeroes(output, headerSize - tableEnd);
    }

    private static byte[] ZlibCompress(byte[] data, CompressionLevel level)
    {
        using var ms = new MemoryStream();
        using (var zs = new ZLibStream(ms, level, leaveOpen: true))
            zs.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    private static void WriteZeroes(Stream output, long count)
    {
        if (count <= 0)
            return;
        var zeros = new byte[0x10000];
        while (count > 0)
        {
            int chunk = (int)Math.Min(count, zeros.Length);
            output.Write(zeros, 0, chunk);
            count -= chunk;
        }
    }
}
