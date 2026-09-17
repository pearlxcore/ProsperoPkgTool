using System.Buffers.Binary;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room writer for the PS5 PFSv3 "PFSC" compression container — the inner
/// per-file image wrapper that is distinct from the zlib "PFSC" image handled by
/// <see cref="ProsperoPfscWriter"/>/<see cref="ProsperoPfscReader"/>. The two share
/// the 4-byte 'PFSC' magic but are disambiguated by the version field at offset 0x04
/// (this format writes 3; the zlib variant writes 0).
///
/// Only the <b>stored</b> (uncompressed) path is implemented here. The reference
/// format's compressed path requires a Kraken encoder, which is intentionally out of
/// scope; every block is emitted stored (isBlockCompressed = 0). The container is
/// still fully valid: each block's per-block SHA3-256 digest and the file-level digest
/// at 0x28 are computed over the uncompressed bytes, so a stored-only container
/// round-trips exactly through a reader.
///
/// On-disk layout (little-endian):
///   0x00 : magic 0x43534650 ('PFSC'), 4 bytes
///   0x04 : format version = 3, 2 bytes
///   0x06 : section count = 7, 2 bytes
///   0x08 : logical block size (256 KiB), 4 bytes
///   0x0C : encode parameter 0x0C (0x0802, Kraken/256KiB/window-18 constant)
///   0x10 : encode parameter 0x10 (u64: algorithm | level&lt;&lt;8 | windowBits&lt;&lt;16)
///   0x18 : uncompressed size, 8 bytes
///   0x20 : total container size, 8 bytes
///   0x28 : file digest (SHA3-256), 32 bytes
///   0x48 : section directory, 7 entries x 16 bytes (id, offset, size)
///   ...  : section 1 (git hash), section 2 (shuffle table), section 3 (block
///          boundary table), section 4 (per-block SHA3-256 hashes), section 5 (aux),
///          section 6 (empty), section 7 (block data, 0x400-aligned).
///
/// The file digest is SHA3-256(header32 || shuffleSection || boundarySection ||
/// blockHashSection), where header32 is the 32-byte aligned struct built from
/// container[0x08..0x20].
/// </summary>
public static class ProsperoPfsv3Writer
{
    /// <summary>Default logical block size for PS5 PFSv3 containers (256 KiB).</summary>
    public const int DefaultBlockSize = 0x40000;

    private const int HeaderSize = 0x48;
    private const int DirectoryEntrySize = 16;
    private const int SectionCount = 7;
    private const int SectionAlignment = 8;
    private const int DataAlignment = 0x400;

    private const uint Magic = 0x43534650;     // 'PFSC' (little-endian)
    private const uint EncodeParam0C = 0x0802; // v3 / Kraken / 256 KiB / window 18
    private const int KrakenAlgorithm = 2;
    private const int DefaultLevel = Compression.KrakenTuning.DefaultLevel;
    private const int WindowBits = 18;

    // Stored-block boundary-table flags (id=3, bits 48..55 of the first u64).
    private const ulong StoredFlagBase = 0x0C;       // bits 50,51 — every stored block
    private const ulong StoredFlagLargeHalf = 0xC0;  // bits 54,55 — size > blockSize/2
    private const ulong BoundaryFlagShift = 48;
    private const ulong SizeHintShift = 44;
    private const ulong SizeHintMax = 0x1FFFF;       // 17-bit saturating (size - 1) hint

    /// <summary>Per-block detail of a compressed PFSv3 container.</summary>
    /// <param name="CompressedSize">Bytes occupied by the block in section 7 (== uncompressed for stored blocks).</param>
    /// <param name="UncompressedSize">Logical plaintext size of the block.</param>
    /// <param name="MultiChunk">True when the Kraken payload spans two 128-KiB sub-chunks.</param>
    /// <param name="FirstChunkCompressedSize">Compressed size of sub-chunk 0 (0 when not multi-chunk).</param>
    /// <param name="Flags">Container boundary flags: 0x02/0x22 for Kraken, 0 for a stored block.</param>
    public readonly record struct CompressedBlock(
        int CompressedSize,
        int UncompressedSize,
        bool MultiChunk,
        int FirstChunkCompressedSize,
        int Flags);

    /// <summary>id=1: 20-byte revision hash (a fixed constant).</summary>
    private static readonly byte[] GitHash =
    [
        0x23, 0x98, 0x7d, 0x16, 0xc9, 0x20, 0x9a, 0xc7, 0x28, 0x37,
        0x19, 0x32, 0x7e, 0x0f, 0x50, 0x6b, 0xbc, 0xf4, 0x59, 0xf4,
    ];

    /// <summary>id=2: 64-byte shuffle-pattern field-width table (constant; shuffle NONE).</summary>
    private static readonly byte[] ShuffleTable =
    [
        0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x08, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x02, 0x02, 0x04, 0x00, 0x00,
        0x01, 0x01, 0x06, 0x01, 0x01, 0x06, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];

    /// <summary>
    /// Builds a stored (uncompressed) PFSv3 compression container for
    /// <paramref name="payload"/> and returns the complete container bytes.
    /// </summary>
    /// <param name="payload">The uncompressed data to wrap.</param>
    /// <param name="blockSize">The logical block size (default 256 KiB). Must be positive.</param>
    /// <param name="level">Kraken level recorded in the container header (default 7). Blocks are stored verbatim.</param>
    public static byte[] WriteStored(ReadOnlySpan<byte> payload, int blockSize = DefaultBlockSize,
        int level = DefaultLevel)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        Compression.KrakenTuning.ValidateLevel(level);

        int blockCount = payload.Length == 0 ? 1 : (payload.Length + blockSize - 1) / blockSize;

        int sec1Size = GitHash.Length;
        int sec2Size = ShuffleTable.Length;
        int sec3Size = (blockCount + 1) * DirectoryEntrySize;
        int sec4Size = blockCount * 32;
        int sec5Size = blockCount * DirectoryEntrySize;

        int off1 = HeaderSize + SectionCount * DirectoryEntrySize;   // 0xB8
        int off2 = Align(off1 + sec1Size, SectionAlignment);
        int off3 = Align(off2 + sec2Size, SectionAlignment);
        int off4 = Align(off3 + sec3Size, SectionAlignment);
        int off5 = Align(off4 + sec4Size, SectionAlignment);
        int off6 = Align(off5 + sec5Size, SectionAlignment);        // id=6 is empty
        int off7 = Align(off6, DataAlignment);                      // block data, padded to 0x400

        long totalSize = (long)off7 + payload.Length;
        var buffer = new byte[checked((int)totalSize)];
        Span<byte> span = buffer;

        // ---- header ----
        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x04..], 3);                 // version 3
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x06..], SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], EncodeParam0C);
        ulong encodeParam10 = (ulong)KrakenAlgorithm
                              | ((ulong)(byte)level << 8)
                              | ((ulong)WindowBits << 16);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x10..], encodeParam10);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x18..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x20..], (ulong)totalSize);

        // ---- section directory @0x48 (ids 1..7) ----
        WriteDirectoryEntry(span, 0, 1, off1, sec1Size);
        WriteDirectoryEntry(span, 1, 2, off2, sec2Size);
        WriteDirectoryEntry(span, 2, 3, off3, sec3Size);
        WriteDirectoryEntry(span, 3, 4, off4, sec4Size);
        WriteDirectoryEntry(span, 4, 5, off5, sec5Size);
        WriteDirectoryEntry(span, 5, 6, off6, 0);
        WriteDirectoryEntry(span, 6, 7, off7, payload.Length);

        // ---- id=1 git hash, id=2 shuffle table ----
        GitHash.CopyTo(span[off1..]);
        ShuffleTable.CopyTo(span[off2..]);

        // ---- id=3 boundary table + id=4 hashes + section-7 data (one pass) ----
        int halfBlock = blockSize / 2;
        long cumulative = 0;
        for (int i = 0; i < blockCount; i++)
        {
            int size = payload.Length == 0
                ? 0
                : (int)Math.Min(blockSize, payload.Length - cumulative);

            ulong flags = StoredFlagBase | (size > halfBlock ? StoredFlagLargeHalf : 0);
            ulong sizeHint = (ulong)Math.Min(Math.Max(size - 1, 0), (long)SizeHintMax);

            int e = off3 + i * DirectoryEntrySize;
            // e0 = compOffset | (shuffle=0 << 44) | (flags << 48); stored => compOffset == uncompOffset.
            BinaryPrimitives.WriteUInt64LittleEndian(span[e..],
                (ulong)cumulative | (flags << (int)BoundaryFlagShift));
            // e1 = uncompOffset | (sizeHint << 44).
            BinaryPrimitives.WriteUInt64LittleEndian(span[(e + 8)..],
                (ulong)cumulative | (sizeHint << (int)SizeHintShift));

            ReadOnlySpan<byte> block = size == 0 ? default : payload.Slice((int)cumulative, size);
            Sha3.Sha3_256(block).CopyTo(span.Slice(off4 + i * 32, 32));

            if (size > 0)
                block.CopyTo(span[(off7 + (int)cumulative)..]);

            cumulative += size;
        }

        // Sentinel boundary entry: totals, no flags / hint.
        int sentinel = off3 + blockCount * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt64LittleEndian(span[sentinel..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(sentinel + 8)..], (ulong)payload.Length);

        // ---- file digest @0x28 = SHA3-256(header32 || id2 || id3 || id4) ----
        byte[] digest = ComputeFileDigest(
            span.Slice(0x08, 24),
            span.Slice(off2, sec2Size),
            span.Slice(off3, sec3Size),
            span.Slice(off4, sec4Size));
        digest.CopyTo(span[0x28..]);

        return buffer;
    }

    /// <summary>
    /// Builds a PFSv3 compression container that Kraken-compresses each <paramref name="blockSize"/>
    /// plaintext block with <see cref="ProsperoPkgTool.Compression.KrakenEncoder.TryEncodeNewLz"/>,
    /// falling back to a stored block whenever the encoder declines or does not shrink the block.
    /// Block digests are always taken over the uncompressed bytes, so the container round-trips
    /// exactly through a reader.
    /// </summary>
    /// <param name="payload">The uncompressed data to wrap.</param>
    /// <param name="blockSize">The logical block size (default 256 KiB). Must be positive.</param>
    /// <param name="level">Kraken level recorded in the container header (default 7).</param>
    public static (byte[] Container, IReadOnlyList<CompressedBlock> Blocks) WriteCompressed(
        ReadOnlySpan<byte> payload, int blockSize = DefaultBlockSize, int level = DefaultLevel,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(blockSize);
        Compression.KrakenTuning.ValidateLevel(level);

        int blockCount = payload.Length == 0 ? 1 : (payload.Length + blockSize - 1) / blockSize;
        var encoded = new byte[blockCount][];
        var info = new CompressedBlock[blockCount];
        var compressed = new bool[blockCount];
        long plainOffset = 0;
        for (int i = 0; i < blockCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int plainSize = payload.Length == 0 ? 0 : (int)Math.Min(blockSize, payload.Length - plainOffset);
            ReadOnlySpan<byte> block = plainSize == 0 ? default : payload.Slice((int)plainOffset, plainSize);
            Compression.KrakenEncoder.EncodedBlock? candidate = plainSize > 0
                ? Compression.KrakenEncoder.TryEncodeNewLz(block)
                : null;
            if (candidate is not null && candidate.Payload.Length < plainSize)
            {
                bool multi = candidate.Flags == 0x22;
                encoded[i] = candidate.Payload;
                compressed[i] = true;
                info[i] = new CompressedBlock(candidate.Payload.Length, plainSize, multi,
                    candidate.FirstChunkCompressedLength, candidate.Flags);
            }
            else
            {
                encoded[i] = block.ToArray();
                info[i] = new CompressedBlock(plainSize, plainSize, false, 0, 0);
            }
            plainOffset += plainSize;
        }

        long compressedTotal = 0;
        for (int i = 0; i < blockCount; i++)
            compressedTotal += encoded[i].Length;

        int sec1Size = GitHash.Length;
        int sec2Size = ShuffleTable.Length;
        int sec3Size = (blockCount + 1) * DirectoryEntrySize;
        int sec4Size = blockCount * 32;
        int sec5Size = blockCount * DirectoryEntrySize;

        int off1 = HeaderSize + SectionCount * DirectoryEntrySize;   // 0xB8
        int off2 = Align(off1 + sec1Size, SectionAlignment);
        int off3 = Align(off2 + sec2Size, SectionAlignment);
        int off4 = Align(off3 + sec3Size, SectionAlignment);
        int off5 = Align(off4 + sec4Size, SectionAlignment);
        int off6 = Align(off5 + sec5Size, SectionAlignment);
        int off7 = Align(off6, DataAlignment);

        long totalSize = (long)off7 + compressedTotal;
        var buffer = new byte[checked((int)totalSize)];
        Span<byte> span = buffer;

        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x04..], 3);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x06..], SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], (uint)blockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x0C..], EncodeParam0C);
        ulong encodeParam10 = (ulong)KrakenAlgorithm
                              | ((ulong)(byte)level << 8)
                              | ((ulong)WindowBits << 16);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x10..], encodeParam10);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x18..], (ulong)payload.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x20..], (ulong)totalSize);

        WriteDirectoryEntry(span, 0, 1, off1, sec1Size);
        WriteDirectoryEntry(span, 1, 2, off2, sec2Size);
        WriteDirectoryEntry(span, 2, 3, off3, sec3Size);
        WriteDirectoryEntry(span, 3, 4, off4, sec4Size);
        WriteDirectoryEntry(span, 4, 5, off5, sec5Size);
        WriteDirectoryEntry(span, 5, 6, off6, 0);
        WriteDirectoryEntry(span, 6, 7, off7, (int)compressedTotal);

        GitHash.CopyTo(span[off1..]);
        ShuffleTable.CopyTo(span[off2..]);

        int halfBlock = blockSize / 2;
        long storedCursor = 0;
        long plainCursor = 0;
        for (int i = 0; i < blockCount; i++)
        {
            CompressedBlock b = info[i];
            int encSize = encoded[i].Length;
            ulong flags;
            ulong sizeHint;
            if (compressed[i])
            {
                flags = (ulong)b.Flags;
                int hint = (b.MultiChunk ? b.FirstChunkCompressedSize : encSize) - 1;
                sizeHint = (ulong)Math.Clamp(hint, 0, (int)SizeHintMax);
            }
            else
            {
                flags = StoredFlagBase | (b.UncompressedSize > halfBlock ? StoredFlagLargeHalf : 0);
                sizeHint = (ulong)Math.Clamp(b.UncompressedSize - 1, 0, (int)SizeHintMax);
            }

            int e = off3 + i * DirectoryEntrySize;
            BinaryPrimitives.WriteUInt64LittleEndian(span[e..], (ulong)storedCursor | (flags << (int)BoundaryFlagShift));
            BinaryPrimitives.WriteUInt64LittleEndian(span[(e + 8)..], (ulong)plainCursor | (sizeHint << (int)SizeHintShift));

            ReadOnlySpan<byte> plaintext = b.UncompressedSize == 0
                ? default : payload.Slice((int)plainCursor, b.UncompressedSize);
            Sha3.Sha3_256(plaintext).CopyTo(span.Slice(off4 + i * 32, 32));

            if (encSize > 0)
                encoded[i].CopyTo(span[(off7 + (int)storedCursor)..]);

            storedCursor += encSize;
            plainCursor += b.UncompressedSize;
        }

        int sentinel = off3 + blockCount * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt64LittleEndian(span[sentinel..], (ulong)compressedTotal);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(sentinel + 8)..], (ulong)payload.Length);

        byte[] digest = ComputeFileDigest(
            span.Slice(0x08, 24),
            span.Slice(off2, sec2Size),
            span.Slice(off3, sec3Size),
            span.Slice(off4, sec4Size));
        digest.CopyTo(span[0x28..]);

        return (buffer, info);
    }

    /// <summary>
    /// Computes the container's file-level SHA3-256 digest. The preimage is
    /// <c>header32 || shuffleSection || boundarySection || blockHashSection</c>, where
    /// <c>header32</c> is a 32-byte little-endian struct:
    /// <c>{u32 1; u32 blockSize; u32 param0C; u32 0 (pad); u64 param10; u64 uncompressedSize}</c>.
    /// </summary>
    private static byte[] ComputeFileDigest(
        ReadOnlySpan<byte> headerParams,
        ReadOnlySpan<byte> shuffleSection,
        ReadOnlySpan<byte> boundarySection,
        ReadOnlySpan<byte> blockHashSection)
    {
        // header32
        Span<byte> header32 = stackalloc byte[32];
        header32.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(header32, 1u);
        headerParams[..8].CopyTo(header32[4..]);   // blockSize (0x08) + param0C (0x0C)
        headerParams[8..].CopyTo(header32[16..]);  // param10 (0x10) + uncompressedSize (0x18)

        int total = header32.Length + shuffleSection.Length + boundarySection.Length + blockHashSection.Length;
        var preimage = new byte[total];
        header32.CopyTo(preimage);
        shuffleSection.CopyTo(preimage.AsSpan(header32.Length));
        boundarySection.CopyTo(preimage.AsSpan(header32.Length + shuffleSection.Length));
        blockHashSection.CopyTo(preimage.AsSpan(header32.Length + shuffleSection.Length + boundarySection.Length));
        return Sha3.Sha3_256(preimage);
    }

    private static void WriteDirectoryEntry(Span<byte> span, int index, ushort id, int offset, int size)
    {
        int p = HeaderSize + index * DirectoryEntrySize;
        BinaryPrimitives.WriteUInt16LittleEndian(span[p..], id);
        BinaryPrimitives.WriteUInt32LittleEndian(span[(p + 2)..], (uint)offset);
        // span[p+6 .. p+10] reserved (0)
        BinaryPrimitives.WriteUInt32LittleEndian(span[(p + 10)..], (uint)size);
        // span[p+14 .. p+16] reserved (0)
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);
}
