using System.Buffers.Binary;
using System.Security.Cryptography;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>The finalized-image variant to emit.</summary>
public enum FihVariant
{
    /// <summary>Debug finalized image (signed byte 0x00) for debug-mode consoles.</summary>
    Debug,

    /// <summary>Official finalized image (signed byte 0x80); retail-key gated.</summary>
    Official,
}

/// <summary>
/// Clean-room builder for the PS5 finalized-image (FIH) header block — the 0x10000-byte
/// little-endian header that fronts the four-segment finalized image layout:
///
///   FIH [0x00000..0x10000) — this header block (header + finalization digest table).
///   PFS [0x10000..0x10000+pfsImageSize) — the shared AES-XTS-encrypted outer PFS image.
///   SC  [pfsEnd..pfsEnd+cntSize) — the embedded \x7FCNT metadata container (its
///        pfs_image_offset at CNT+0x410 points back to the shared image at 0x10000).
///   SI  [scEnd..EOF) — a ZIP archive of install-time metadata (optional).
///
/// The signed byte at offset 0x05 distinguishes the variants: 0x00 = debug, 0x80 = official.
///
/// Header fields (little-endian): magic "\x7FFIH" @0x00, format version 3 @0x06,
/// PFS image offset (0x10000) @0x10, PFS image size @0x18, embedded-CNT offset @0x58,
/// superblock offset @0x20 / size @0x28, game-digest (SHA3-256 of the plaintext outer superblock)
/// stored three times at 0x30/0x70/0xD0, inner-image accounting at 0x50/0x90-0xA8,
/// and the nested-image-content digest at 0xB0.
/// </summary>
public static class ProsperoFihBuilder
{
    public const int HeaderRegionSize = 0x10000;
    private const int SignedByteOffset = 0x05;
    private const int PfsImageOffsetField = 0x10;
    private const int PfsImageSizeField = 0x18;
    private const int EmbeddedCntOffsetField = 0x58;
    private const int DataRegionBlockCountField = 0x50;
    private const int InnerImageBlockCountField = 0x90;
    private const int MetaBlockCountField = 0x94;
    private const int MetaBlockCountMirrorField = 0x98;
    private const int ContentVersionField = 0x9C;
    private const int InnerImageSizeField = 0xA0;
    private const int InnerImageLogicalSizeField = 0xA8;
    private const int OuterFileCountField = 0xF0;
    private const int SparseAfidHoleCountField = 0xF4;
    private const int FlatPathTableBlockCountField = 0xF8;
    private const int EmptyFileCountField = 0xFC;

    private const uint OuterFileCountNwonly = 1;
    private const uint FlatPathTableBlockCountNwonly = 2;

    /// <summary>
    /// Build the 0x10000-byte FIH header block for the given outer PFS image. The image is scanned
    /// for its plaintext superblock (version 2 @+0x00, magic 0x0B2A3301 @+0x08) to compute the
    /// game-digest and the inner-image accounting fields.
    /// </summary>
    /// <param name="variant">Debug (signed byte 0) or Official (signed byte 0x80).</param>
    /// <param name="pfsImageSize">Size of the shared encrypted outer PFS image.</param>
    /// <param name="embeddedCntOffset">FIH-relative offset of the embedded CNT container.</param>
    /// <param name="image">The encrypted outer PFS image bytes (the superblock stays plaintext).</param>
    /// <param name="nestedImageDigest">The FIH 0xB0 nested-image-content digest (SHA3-256 of the
    /// inner <c>naps_pkg_layout.dat</c>); when null, falls back to SHA3-256 of the outer image.</param>
    /// <param name="nestedImageSize">Length of the 0xB0 digest preimage (the naps file length).</param>
    /// <param name="nestedMetaBaseBlocks">Inner mount data-region block count (installer field).</param>
    /// <param name="contentVersionHi">High 32 bits of the content-version word (major BCD &lt;&lt; 24).</param>
    /// <param name="innerContentInodes">Inner content-inode count (dirs+files below uroot).</param>
    /// <param name="appFileCount">Application-payload (non-sce_sys) regular file count.</param>
    /// <param name="metaBlockCount">FIH 0x94: the NAPS FIDX file count (<c>NAPS NumFiles − 1</c>).</param>
    /// <param name="metaBlockCountMirror">FIH 0x98: 0x94 + empty-file count.</param>
    /// <param name="emptyFileCount">FIH 0xFC: zero-length inner file count.</param>
    /// <param name="sparseAfidHoleCount">FIH 0xF4: sparse AFID hole count.</param>
    public static byte[] BuildHeaderBlock(
        FihVariant variant,
        ulong pfsImageSize,
        ulong embeddedCntOffset,
        ReadOnlySpan<byte> image,
        byte[]? nestedImageDigest = null,
        long nestedImageSize = 0,
        long nestedMetaBaseBlocks = 0,
        uint contentVersionHi = 0,
        int innerContentInodes = 0,
        int appFileCount = 0,
        int metaBlockCount = 0,
        int metaBlockCountMirror = 0,
        int emptyFileCount = 0,
        int sparseAfidHoleCount = 0)
    {
        var h = new byte[HeaderRegionSize];

        // ---- Structural fields (little-endian). ----
        h[0] = 0x7F; h[1] = (byte)'F'; h[2] = (byte)'I'; h[3] = (byte)'H';
        h[4] = 0x01;
        h[SignedByteOffset] = variant == FihVariant.Official ? (byte)0x80 : (byte)0x00;
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(0x06), 3);        // format version
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(0x08), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(PfsImageOffsetField), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(PfsImageSizeField), pfsImageSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(EmbeddedCntOffsetField), embeddedCntOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x60), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x68), 0x800000000000UL);

        // 0x50: inner mount data-region block count (installer pre-allocation field).
        if (nestedMetaBaseBlocks > 0)
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(DataRegionBlockCountField), (ulong)nestedMetaBaseBlocks);

        // ---- Digest table. ----
        int sbOffset = LocateSuperblock(image);
        if (sbOffset >= 0)
        {
            byte[] gameDigest = Sha3.Sha3_256(image.Slice(sbOffset, HeaderRegionSize));
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x20), (ulong)(HeaderRegionSize + sbOffset));
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), HeaderRegionSize);
            gameDigest.CopyTo(h.AsSpan(0x30, 32));
            gameDigest.CopyTo(h.AsSpan(0x70, 32));
            gameDigest.CopyTo(h.AsSpan(0xD0, 32));

            // ---- Inner-image accounting (data-first nwonly layout). ----
            long sbBlockIndex = (long)sbOffset / HeaderRegionSize;
            long totalBlocks = (long)pfsImageSize / HeaderRegionSize;
            if (sbBlockIndex >= 1 && sbOffset % HeaderRegionSize == 0 &&
                (long)pfsImageSize % HeaderRegionSize == 0 && totalBlocks > sbBlockIndex)
            {
                bool nwonly = innerContentInodes > 0;
                // 0x90 = 64 KiB blocks occupied by pfs_image.dat. The outer layout places the
                // naps_pkg_layout.dat file between the data and the plaintext superblock, so the
                // field is the superblock index minus the NAPS file's block span (not just one
                // block). Callers with no NAPS length keep the historical single-block gap.
                long napsBlocks = nestedImageSize > 0
                    ? (nestedImageSize + HeaderRegionSize - 1) / HeaderRegionSize
                    : 1;
                uint innerBlocks = (uint)(sbBlockIndex - napsBlocks);
                uint metaOrInodes = nwonly ? (uint)innerContentInodes : (uint)(totalBlocks - innerBlocks);
                // 0x94/0x98: the inner metadata block count and its mirror. The values are derived
                // from the image geometry unless the caller threads in exact values (Sony's own
                // builder writes different values to the two fields in the reference packages).
                uint metaCount = metaBlockCount > 0 ? (uint)metaBlockCount : metaOrInodes;
                uint metaMirror = metaBlockCountMirror > 0 ? (uint)metaBlockCountMirror : metaOrInodes;
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(InnerImageBlockCountField), innerBlocks);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(MetaBlockCountField), metaCount);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(MetaBlockCountMirrorField), metaMirror);
                BinaryPrimitives.WriteUInt64LittleEndian(
                    h.AsSpan(InnerImageSizeField), (ulong)innerBlocks * (ulong)HeaderRegionSize);

                if (contentVersionHi != 0)
                    BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ContentVersionField), contentVersionHi);

                if (nestedImageSize > 0)
                    BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(InnerImageLogicalSizeField), (ulong)nestedImageSize);

                uint outerFileCount = nwonly && appFileCount > 0 ? (uint)appFileCount : OuterFileCountNwonly;
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(OuterFileCountField), outerFileCount);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(SparseAfidHoleCountField), (uint)sparseAfidHoleCount);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(FlatPathTableBlockCountField), FlatPathTableBlockCountNwonly);
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(EmptyFileCountField), (uint)emptyFileCount);
            }
        }
        else
        {
            // No plaintext superblock: best-effort fallback digest over the whole image.
            byte[] fallback = Sha3.Sha3_256(image);
            fallback.CopyTo(h.AsSpan(0x30, 32));
            fallback.CopyTo(h.AsSpan(0x70, 32));
            fallback.CopyTo(h.AsSpan(0xD0, 32));
        }

        // 0xB0: the nested-image-content digest (SHA3-256 of the inner naps file), or a fallback
        // SHA3-256 of the outer image when the caller has no inner preimage.
        byte[] slotB0 = nestedImageDigest is { Length: 32 }
            ? nestedImageDigest
            : Sha3.Sha3_256(image);
        slotB0.CopyTo(h.AsSpan(0xB0, 32));

        return h;
    }

    /// <summary>
    /// Builds the 0x10000-byte FIH header block from an already-located plaintext outer superblock
    /// block. Equivalent to <see cref="BuildHeaderBlock"/>'s superblock branch but without requiring
    /// the whole (possibly file-backed) outer image: <paramref name="superblockBlock"/> is the
    /// plaintext superblock and <paramref name="superblockOffset"/> its image-relative offset.
    /// </summary>
    public static byte[] BuildHeaderBlockFromSuperblock(
        FihVariant variant,
        ulong pfsImageSize,
        ulong embeddedCntOffset,
        ReadOnlySpan<byte> superblockBlock,
        long superblockOffset,
        byte[]? nestedImageDigest = null,
        long nestedImageSize = 0,
        long nestedMetaBaseBlocks = 0,
        uint contentVersionHi = 0,
        int innerContentInodes = 0,
        int appFileCount = 0,
        int metaBlockCount = 0,
        int metaBlockCountMirror = 0,
        int emptyFileCount = 0,
        int sparseAfidHoleCount = 0)
    {
        var h = new byte[HeaderRegionSize];

        // ---- Structural fields (little-endian). ----
        h[0] = 0x7F; h[1] = (byte)'F'; h[2] = (byte)'I'; h[3] = (byte)'H';
        h[4] = 0x01;
        h[SignedByteOffset] = variant == FihVariant.Official ? (byte)0x80 : (byte)0x00;
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(0x06), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(0x08), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(PfsImageOffsetField), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(PfsImageSizeField), pfsImageSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(EmbeddedCntOffsetField), embeddedCntOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x60), HeaderRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x68), 0x800000000000UL);

        if (nestedMetaBaseBlocks > 0)
            BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(DataRegionBlockCountField), (ulong)nestedMetaBaseBlocks);

        // ---- Digest table (superblock known). ----
        byte[] gameDigest = Sha3.Sha3_256(superblockBlock);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x20), (ulong)(HeaderRegionSize + superblockOffset));
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0x28), HeaderRegionSize);
        gameDigest.CopyTo(h.AsSpan(0x30, 32));
        gameDigest.CopyTo(h.AsSpan(0x70, 32));
        gameDigest.CopyTo(h.AsSpan(0xD0, 32));

        // ---- Inner-image accounting (data-first nwonly layout). ----
        long sbBlockIndex = superblockOffset / HeaderRegionSize;
        long totalBlocks = (long)pfsImageSize / HeaderRegionSize;
        if (sbBlockIndex >= 1 && superblockOffset % HeaderRegionSize == 0 &&
            (long)pfsImageSize % HeaderRegionSize == 0 && totalBlocks > sbBlockIndex)
        {
            bool nwonly = innerContentInodes > 0;
            // 0x90 = 64 KiB blocks occupied by pfs_image.dat (superblock index minus the NAPS file's
            // block span; see BuildHeaderBlock).
            long napsBlocks = nestedImageSize > 0
                ? (nestedImageSize + HeaderRegionSize - 1) / HeaderRegionSize
                : 1;
            uint innerBlocks = (uint)(sbBlockIndex - napsBlocks);
            uint metaOrInodes = nwonly ? (uint)innerContentInodes : (uint)(totalBlocks - innerBlocks);
            uint metaCount = metaBlockCount > 0 ? (uint)metaBlockCount : metaOrInodes;
            uint metaMirror = metaBlockCountMirror > 0 ? (uint)metaBlockCountMirror : metaOrInodes;
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(InnerImageBlockCountField), innerBlocks);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(MetaBlockCountField), metaCount);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(MetaBlockCountMirrorField), metaMirror);
            BinaryPrimitives.WriteUInt64LittleEndian(
                h.AsSpan(InnerImageSizeField), (ulong)innerBlocks * (ulong)HeaderRegionSize);

            if (contentVersionHi != 0)
                BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(ContentVersionField), contentVersionHi);

            if (nestedImageSize > 0)
                BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(InnerImageLogicalSizeField), (ulong)nestedImageSize);

            uint outerFileCount = nwonly && appFileCount > 0 ? (uint)appFileCount : OuterFileCountNwonly;
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(OuterFileCountField), outerFileCount);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(SparseAfidHoleCountField), (uint)sparseAfidHoleCount);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(FlatPathTableBlockCountField), FlatPathTableBlockCountNwonly);
            BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(EmptyFileCountField), (uint)emptyFileCount);
        }

        // 0xB0: the nested-image-content digest, or the game digest when no inner preimage exists.
        byte[] slotB0 = nestedImageDigest is { Length: 32 } ? nestedImageDigest : gameDigest;
        slotB0.CopyTo(h.AsSpan(0xB0, 32));

        return h;
    }

    /// <summary>
    /// Wraps a CNT container into a complete finalized image: FIH header + shared PFS image +
    /// embedded CNT (+ optional trailing SI segment). The embedded CNT's pfs_image_offset (CNT+0x410)
    /// must already point at the FIH-relative 0x10000.
    /// </summary>
    public static byte[] BuildFromCnt(
        byte[] cnt, FihVariant variant = FihVariant.Debug,
        byte[]? nestedImageDigest = null, long nestedImageSize = 0, long nestedMetaBaseBlocks = 0,
        uint contentVersionHi = 0, int innerContentInodes = 0, int appFileCount = 0,
        int metaBlockCount = 0, int metaBlockCountMirror = 0,
        int emptyFileCount = 0, int sparseAfidHoleCount = 0,
        byte[]? siSegment = null)
    {
        ArgumentNullException.ThrowIfNull(cnt);

        // The embedded image is physically laid out after the CNT body (body_offset + body_size).
        // CNT+0x410 is the FIH-relative image offset in the FINALIZED package, not the container
        // offset, so it must not be used to split the still-embedded container.
        ulong bodyOffset = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x20));
        ulong bodySize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x28));
        ulong pfsImageSize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x418));
        ulong pfsImageOffset = bodyOffset + bodySize;
        if (bodyOffset == 0 || pfsImageSize == 0 ||
            pfsImageOffset + pfsImageSize > (ulong)cnt.Length)
            throw new InvalidDataException("CNT container has no embedded PFS image to finalize.");

        // Split the CNT: metadata (everything before the image) + the shared image.
        int metaLen = (int)pfsImageOffset;
        byte[] metadata = cnt.AsSpan(0, metaLen).ToArray();
        byte[] image = cnt.AsSpan(metaLen, (int)pfsImageSize).ToArray();

        // In the finalized image the embedded CNT's pfs_image_offset must point at the shared
        // image stored at the start of the body region (FIH offset 0x10000).
        BinaryPrimitives.WriteUInt64BigEndian(metadata.AsSpan(0x410), HeaderRegionSize);

        ulong embeddedCntOffset = HeaderRegionSize + pfsImageSize;
        byte[] header = BuildHeaderBlock(
            variant, pfsImageSize, embeddedCntOffset, image,
            nestedImageDigest, nestedImageSize, nestedMetaBaseBlocks,
            contentVersionHi, innerContentInodes, appFileCount,
            metaBlockCount, metaBlockCountMirror, emptyFileCount, sparseAfidHoleCount);

        using var ms = new MemoryStream(
            checked((int)(HeaderRegionSize + (long)pfsImageSize + metaLen + (siSegment?.Length ?? 0))));
        ms.Write(header);
        ms.Write(image);
        ms.Write(metadata);
        if (siSegment is { Length: > 0 })
            ms.Write(siSegment);
        return ms.ToArray();
    }

    /// <summary>
    /// File-backed counterpart of <see cref="BuildFromCnt"/>: streams the CNT's embedded PFS image
    /// into the finalized output instead of materializing it, so images above the in-memory array
    /// limit are supported. The 0x10000-byte header is written first, then the shared image, then the
    /// rewritten CNT metadata. When <paramref name="siFactory"/> is supplied it is called with the
    /// still-open read/write output positioned after the mount image; a non-empty result is appended
    /// as the trailing SI segment.
    /// </summary>
    /// <param name="cntPath">Path to the standalone CNT (metadata + embedded PFS image).</param>
    /// <param name="outputPath">Destination for the finalized FIH image.</param>
    /// <param name="variant">Debug or Official finalized variant.</param>
    /// <param name="outerSuperblockIndex">Image block index of the plaintext outer superblock, or
    /// -1 to scan the embedded image for it.</param>
    /// <param name="siFactory">Optional SI-segment builder given the output stream and the mount
    /// image length (FIH + PFS + CNT, excluding SI).</param>
    public static void BuildFromCntToFile(
        string cntPath, string outputPath, FihVariant variant, int outerSuperblockIndex,
        byte[]? nestedImageDigest, long nestedImageSize, long nestedMetaBaseBlocks,
        uint contentVersionHi, int innerContentInodes, int appFileCount,
        int metaBlockCount, int metaBlockCountMirror, int emptyFileCount, int sparseAfidHoleCount,
        Func<Stream, long, byte[]>? siFactory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cntPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        using var cnt = new FileStream(Path.GetFullPath(cntPath), FileMode.Open, FileAccess.Read,
            FileShare.Read, 1 << 20, FileOptions.RandomAccess);

        byte[] head = new byte[0x1000];
        if (!ReadFullyAt(cnt, 0, head))
            throw new InvalidDataException("CNT container is too small.");

        ulong bodyOffset = BinaryPrimitives.ReadUInt64BigEndian(head.AsSpan(0x20));
        ulong bodySize = BinaryPrimitives.ReadUInt64BigEndian(head.AsSpan(0x28));
        ulong pfsImageSize = BinaryPrimitives.ReadUInt64BigEndian(head.AsSpan(0x418));
        if (bodyOffset == 0 || pfsImageSize == 0)
            throw new InvalidDataException("CNT container has no embedded PFS image to finalize.");

        long metaLen = checked((long)bodyOffset + (long)bodySize);
        if (metaLen > int.MaxValue)
            throw new NotSupportedException(
                $"The CNT metadata region ({metaLen} bytes) exceeds the in-memory limit.");
        if (metaLen + (long)pfsImageSize > cnt.Length)
            throw new InvalidDataException("CNT container has no embedded PFS image to finalize.");

        byte[] metadata = new byte[metaLen];
        if (!ReadFullyAt(cnt, 0, metadata))
            throw new InvalidDataException("Failed to read the CNT metadata region.");
        BinaryPrimitives.WriteUInt64BigEndian(metadata.AsSpan(0x410), HeaderRegionSize);

        long superblockOffset = outerSuperblockIndex >= 0
            ? (long)outerSuperblockIndex * HeaderRegionSize
            : LocateSuperblock(cnt, metaLen, (long)pfsImageSize);
        if (superblockOffset < 0 || superblockOffset + HeaderRegionSize > (long)pfsImageSize)
            throw new InvalidDataException("Plaintext outer superblock not found in the embedded PFS image.");

        byte[] superblockBlock = new byte[HeaderRegionSize];
        if (!ReadFullyAt(cnt, metaLen + superblockOffset, superblockBlock))
            throw new InvalidDataException("Failed to read the outer superblock block.");

        ulong embeddedCntOffset = HeaderRegionSize + pfsImageSize;
        byte[] header = BuildHeaderBlockFromSuperblock(
            variant, pfsImageSize, embeddedCntOffset, superblockBlock, superblockOffset,
            nestedImageDigest, nestedImageSize, nestedMetaBaseBlocks, contentVersionHi,
            innerContentInodes, appFileCount, metaBlockCount, metaBlockCountMirror,
            emptyFileCount, sparseAfidHoleCount);

        string full = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());
        using var outFs = new FileStream(full, FileMode.Create, FileAccess.ReadWrite, FileShare.None,
            1 << 20, FileOptions.None);
        outFs.Write(header, 0, header.Length);

        cnt.Position = metaLen;
        CopyBytes(cnt, outFs, (long)pfsImageSize);

        outFs.Write(metadata, 0, metadata.Length);
        outFs.Flush();
        long mountLength = outFs.Length;

        if (siFactory is not null)
        {
            byte[] si = siFactory(outFs, mountLength);
            if (si is { Length: > 0 })
            {
                outFs.Position = mountLength;
                outFs.Write(si, 0, si.Length);
            }
        }
        outFs.Flush();
    }

    /// <summary>
    /// Locates the plaintext outer superblock within a streamed region (version u64 == 2 at +0x00
    /// and magic 0x0B2A3301 at +0x08), returning the byte offset relative to
    /// <paramref name="start"/>, or -1.
    /// </summary>
    public static int LocateSuperblock(Stream stream, long start, long length, int blockSize = HeaderRegionSize)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (blockSize <= 0x10 || length < blockSize)
            return -1;

        byte[] block = new byte[blockSize];
        long end = start + length;
        for (long off = start; off + blockSize <= end; off += blockSize)
        {
            if (!ReadFullyAt(stream, off, block))
                break;
            if (BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(0, 8)) == 2UL &&
                block.AsSpan(8, 4).SequenceEqual((ReadOnlySpan<byte>)[0x0B, 0x2A, 0x33, 0x01]))
                return (int)(off - start);
        }
        return -1;
    }

    private static void CopyBytes(Stream source, Stream destination, long count)
    {
        byte[] buffer = new byte[1 << 20];
        long remaining = count;
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(buffer.Length, remaining);
            int read = source.Read(buffer, 0, toRead);
            if (read <= 0)
                throw new EndOfStreamException("Unexpected end of the source while copying the embedded PFS image.");
            destination.Write(buffer, 0, read);
            remaining -= read;
        }
    }

    private static bool ReadFullyAt(Stream stream, long offset, byte[] buffer)
    {
        stream.Position = offset;
        int read = 0;
        while (read < buffer.Length)
        {
            int n = stream.Read(buffer, read, buffer.Length - read);
            if (n <= 0)
                return false;
            read += n;
        }
        return true;
    }

    /// <summary>
    /// Locates the plaintext outer superblock within an (encrypted) outer-PFS image: scans
    /// block-aligned offsets for version u64 == 2 at +0x00 and magic 0x0B2A3301 at +0x08.
    /// Returns the byte offset, or -1.
    /// </summary>
    public static int LocateSuperblock(ReadOnlySpan<byte> image, int blockSize = HeaderRegionSize)
    {
        if (blockSize <= 0x10)
            return -1;
        for (int off = 0; off + blockSize <= image.Length; off += blockSize)
        {
            if (BinaryPrimitives.ReadUInt64LittleEndian(image.Slice(off, 8)) == 2UL &&
                image.Slice(off + 8, 4).SequenceEqual((ReadOnlySpan<byte>)[0x0B, 0x2A, 0x33, 0x01]))
                return off;
        }
        return -1;
    }
}
