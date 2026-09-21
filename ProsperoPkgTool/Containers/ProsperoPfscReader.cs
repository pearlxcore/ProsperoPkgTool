using System.Buffers.Binary;
using System.IO.Compression;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room reader for the PS5 "zlib PFSC" container produced by
/// <see cref="ProsperoPfscWriter"/>. Parses the header, block-offset table, and
/// payload, and reassembles the original data, decoding per-block zlib-compressed
/// blocks when present. This mirrors the writer byte-for-byte so a round-trip
/// (<c>Read(Write(x)) == x</c>) holds exactly.
/// </summary>
public static class ProsperoPfscReader
{
    /// <summary>
    /// Parse a PFSC container and return its payload bytes. The logical payload length is
    /// recovered from the data-length field; each block is decoded from the pointer table
    /// (a block whose size differs from the block size is a zlib stream with a 2-byte header).
    /// </summary>
    public static byte[] Read(ReadOnlySpan<byte> container)
    {
        if (container.Length < 0x30)
            throw new InvalidDataException("PFSC container is too small.");

        if (BinaryPrimitives.ReadUInt32LittleEndian(container[0x00..]) != ProsperoPfscWriter.Magic)
            throw new InvalidDataException("Missing 'PFSC' magic.");

        if (BinaryPrimitives.ReadInt32LittleEndian(container[0x04..]) != 0)
            throw new InvalidDataException("PFSC unk4 field is not zero.");

        int blockSize = BinaryPrimitives.ReadInt32LittleEndian(container[0x0C..]);
        long blockSize64 = BinaryPrimitives.ReadInt64LittleEndian(container[0x10..]);
        long pointerTable = BinaryPrimitives.ReadInt64LittleEndian(container[0x18..]);
        long dataStart = (long)BinaryPrimitives.ReadUInt64LittleEndian(container[0x20..]);
        long dataLength = BinaryPrimitives.ReadInt64LittleEndian(container[0x28..]);

        if (blockSize != ProsperoPfscWriter.BlockSize)
            throw ProsperoErrorInfo.Unsupported($"Unsupported PFSC block size {blockSize}.");
        if (blockSize64 != blockSize)
            throw new InvalidDataException("PFSC block-size fields disagree.");

        if (pointerTable <= 0 || pointerTable >= container.Length)
            throw new InvalidDataException("PFSC pointer-table offset is out of range.");
        if (dataStart < 0 || dataStart > container.Length)
            throw new InvalidDataException("PFSC data start is out of range.");
        if (dataLength < 0 || dataLength % blockSize != 0)
            throw new InvalidDataException("PFSC data length is not a whole number of blocks.");

        // dataLength is the *uncompressed* logical length (numBlocks * blockSize); the actual
        // on-disk extent is recovered from the pointer table (sentinel = end of data).
        long numBlocks = dataLength / blockSize;
        long pointerTableEnd = pointerTable + (numBlocks + 1) * 8;
        if (pointerTableEnd > container.Length)
            throw new InvalidDataException("PFSC pointer table extends past the container.");
        var output = new byte[dataLength];

        for (long i = 0; i < numBlocks; i++)
        {
            int e = (int)(pointerTable + i * 8);
            long off = BinaryPrimitives.ReadInt64LittleEndian(container[e..]);
            long next = BinaryPrimitives.ReadInt64LittleEndian(container[(e + 8)..]);
            int blockSizeOnDisk = (int)(next - off);
            if (blockSizeOnDisk <= 0 || blockSizeOnDisk > blockSize)
                throw new InvalidDataException($"PFSC block {i} has an invalid size {blockSizeOnDisk}.");

            var dst = output.AsSpan((int)(i * blockSize), blockSize);
            if (blockSizeOnDisk == blockSize)
            {
                // Stored raw block.
                container.Slice((int)off, blockSize).CopyTo(dst);
            }
            else
            {
                // Compressed: skip the 2-byte zlib header, inflate the DEFLATE remainder.
                using var ms = new MemoryStream(
                    container.Slice((int)off + 2, blockSizeOnDisk - 2).ToArray(), writable: false);
                using var ds = new DeflateStream(ms, CompressionMode.Decompress);
                ds.ReadExactly(dst);
            }
        }

        return output;
    }
}
