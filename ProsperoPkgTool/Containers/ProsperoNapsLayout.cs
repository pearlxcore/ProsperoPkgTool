using System.Buffers.Binary;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room decoder/serializer for the PS5 NAPS streaming layout
/// (<c>naps_pkg_layout.dat</c>), the sibling of the data-first inner image
/// (<c>pfs_image.dat</c>). It records, per block, how the Kraken-compressed inner
/// image is laid out so the inner PFS mount can be reconstructed (FINDINGS.md §5).
///
/// On-disk order (fixed strides):
///   header (16) -> outer-block digests (8 each) -> shuffle patterns (8 each) ->
///   fidx per-file offsets (6 each) -> u2c offsets (10 each) -> CblockInfo (9 each).
///
/// The header packs two 64-bit words; the 9-byte CblockInfo record bit-packs a
/// run-base marker plus either a per-block field set or a run-anchor field set.
/// <see cref="Parse"/> decodes a blob and <see cref="BuildLayout"/> re-serializes it
/// such that <c>BuildLayout(Parse(x)) == x</c> byte-for-byte (including trailing pad).
/// </summary>
public static class ProsperoNapsLayout
{
    public const string FileName = "naps_pkg_layout.dat";

    public const int HeaderSize = 16;
    public const int OuterBlockDigestStride = 8;
    public const int ShufflePatternStride = 8;
    public const int FileOffsetStride = 6;
    public const int U2cStride = 10;
    public const int CblockInfoStride = 9;

    /// <summary>Default trailing zero-pad alignment of a serialized layout blob.</summary>
    public const int DefaultAlignment = 16;

    /// <summary>
    /// Compute the absolute offset of the CblockInfo section from a raw NAPS blob, using the
    /// Sony-native layout formula (verified byte-exact against the debug, retail and exp
    /// packages; FINDINGS.md §5). The on-disk sections before CblockInfo are:
    ///   header (16) + outer digests (8·NumOuterBlocks) + shuffle patterns (8·NumShufflePatterns)
    ///   + fidx (6·(NumFiles−1) + residue) + u2c (10·(floor(NumUBlocks/8)+1)),
    /// where the fidx residue is <c>10 + NumShufflePatterns·…</c> and is folded into the formula's
    /// constant so callers never need to model the compressor residue directly.
    /// </summary>
    public static long ComputeCblockInfoBase(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderSize)
            throw new ArgumentException($"NAPS header needs {HeaderSize} bytes.", nameof(header));

        ulong word0 = BinaryPrimitives.ReadUInt64LittleEndian(header);
        ulong word1 = BinaryPrimitives.ReadUInt64LittleEndian(header[8..]);

        uint numFilesField = (uint)(word0 & 0xFFFFFF);       // raw, no +1 sentinel
        uint fieldA = (uint)((word0 >> 28) & 0xF);           // = NumShufflePatterns
        uint nu = (uint)((word0 >> 32) & 0xFFFFFF);
        uint numOuter = (uint)(word1 & 0xFFFFFF);

        long raw = (long)(fieldA + numOuter) * 8
                 + 10L * ((nu + 8) >> 3)
                 + 6L * numFilesField
                 + 29L;
        return raw & ~7L; // align8
    }

    /// <summary>Counts-based equivalent of <see cref="ComputeCblockInfoBase(ReadOnlySpan{byte})"/>.</summary>
    public static long ComputeCblockInfoBase(NapsLayoutCounts counts)
    {
        long raw = (long)(counts.NumShufflePatterns + counts.NumOuterBlocks) * 8
                 + 10L * ((counts.NumUBlocks + 8) >> 3)
                 + 6L * (counts.NumFiles - 1)
                 + 29L;
        return raw & ~7L; // align8
    }

    /// <summary>
    /// Compute the absolute offset of the u2c section from the counts (native <c>sub_1402defe0</c>):
    /// <c>(fieldA + numOuter)*8 + 6*numFilesField + 22</c>, where <c>numFilesField = NumFiles - 1</c>
    /// (raw, no sentinel). This is exactly <c>header(16) + outer(8·numOuter) + shuffle(8·numShuffle)
    /// + fidx(6·numFiles)</c> — the u2c section immediately follows the fidx section with no trailer.
    /// </summary>
    public static long ComputeU2cOffset(NapsLayoutCounts counts)
    {
        long ofs = (long)(counts.NumShufflePatterns + counts.NumOuterBlocks) * 8
                 + 6L * (counts.NumFiles - 1)
                 + 22L;
        return ofs;
    }

    /// <summary>Decode the 16-byte header into section counts.</summary>
    public static NapsLayoutCounts DecodeHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderSize)
            throw new ArgumentException($"NAPS header needs {HeaderSize} bytes.", nameof(header));

        ulong word0 = BinaryPrimitives.ReadUInt64LittleEndian(header);
        ulong word1 = BinaryPrimitives.ReadUInt64LittleEndian(header[8..]);

        int numFiles = (int)(word0 & 0xFFFFFF) + 1;
        byte compressionType = (byte)((word0 >> 24) & 0x3);
        int numKeys = (int)((word0 >> 26) & 0x3) + 1;
        int numShufflePatterns = (int)((word0 >> 28) & 0xF);
        int numUBlocks = (int)((word0 >> 32) & 0xFFFFFF);

        int numOuterBlocks = (int)(word1 & 0xFFFFFF);
        int numCblockInfo = (int)((word1 >> 24) & 0xFFFFFF) + 2;

        return new NapsLayoutCounts(
            numFiles, compressionType, numKeys, numShufflePatterns,
            numUBlocks, numOuterBlocks, numCblockInfo);
    }

    /// <summary>Encode section counts back into a 16-byte header (inverse of <see cref="DecodeHeader"/>).</summary>
    public static byte[] EncodeHeader(NapsLayoutCounts counts)
    {
        ulong word0 =
              ((ulong)(uint)(counts.NumFiles - 1) & 0xFFFFFF)
            | ((ulong)(counts.CompressionType & 0x3) << 24)
            | ((ulong)(uint)((counts.NumKeys - 1) & 0x3) << 26)
            | ((ulong)(uint)(counts.NumShufflePatterns & 0xF) << 28)
            | ((ulong)(uint)(counts.NumUBlocks & 0xFFFFFF) << 32);

        ulong word1 =
              ((ulong)(uint)(counts.NumOuterBlocks & 0xFFFFFF))
            | ((ulong)(uint)((counts.NumCblockInfo - 2) & 0xFFFFFF) << 24);

        var header = new byte[HeaderSize];
        BinaryPrimitives.WriteUInt64LittleEndian(header, word0);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(8), word1);
        return header;
    }

    /// <summary>
    /// Compute the offset/size of every section from the counts using the Sony-native section
    /// placement (FINDINGS.md §5, verified byte-exact against debug + retail):
    ///   header (16) -> outer digests (8·NumOuterBlocks) -> shuffle (8·NumShufflePatterns)
    ///   -> fidx (6·NumFiles, includes sentinel) -> u2c (10·(floor(NumUBlocks/8)+1), immediately after
    ///   fidx) -> [alignment pad] -> CblockInfo (9·NumCblockInfo, at <see cref="ComputeCblockInfoBase"/>).
    /// The CblockInfo section is NOT placed contiguously after u2c: it begins at the align8
    /// offset returned by <see cref="ComputeCblockInfoBase(NapsLayoutCounts)"/>, leaving a small
    /// zero-pad (<see cref="NapsSectionMap.CblockInfoPad"/>) between u2c and CblockInfo.
    /// </summary>
    public static NapsSectionMap SectionMap(NapsLayoutCounts counts)
    {
        long pos = 0;
        var header = new NapsSection(pos, HeaderSize, HeaderSize, 1);
        pos += header.Size;

        var outerBlocks = new NapsSection(pos, (long)counts.NumOuterBlocks * OuterBlockDigestStride,
            OuterBlockDigestStride, counts.NumOuterBlocks);
        pos += outerBlocks.Size;

        var shuffles = new NapsSection(pos, (long)counts.NumShufflePatterns * ShufflePatternStride,
            ShufflePatternStride, counts.NumShufflePatterns);
        pos += shuffles.Size;

        var fidx = new NapsSection(pos, (long)counts.NumFiles * FileOffsetStride,
            FileOffsetStride, counts.NumFiles);
        pos += fidx.Size;

        int u2cCount = counts.NumU2cEntries;
        var u2c = new NapsSection(pos, (long)u2cCount * U2cStride, U2cStride, u2cCount);
        pos += u2c.Size;

        long cbiBase = ComputeCblockInfoBase(counts);
        long cbiPad = cbiBase - pos;
        var cbi = new NapsSection(cbiBase, (long)counts.NumCblockInfo * CblockInfoStride,
            CblockInfoStride, counts.NumCblockInfo);
        pos = cbiBase + cbi.Size;

        return new NapsSectionMap(header, outerBlocks, shuffles, fidx, u2c, cbi, cbiPad, pos);
    }

    /// <summary>The number of 6-byte fidx entries for a blob (equals <see cref="NapsLayoutCounts.NumFiles"/>).</summary>
    public static int DeriveFidxEntryCount(NapsLayoutCounts counts, long blobLength)
        => counts.NumFiles;

    /// <summary>Decode a 6-byte fidx entry (40-bit LE offset + 1 type byte).</summary>
    public static NapsFileOffsetEntry DecodeFileOffsetEntry(ReadOnlySpan<byte> entry)
    {
        if (entry.Length < FileOffsetStride)
            throw new ArgumentException($"fidx entry needs {FileOffsetStride} bytes.", nameof(entry));

        ulong offset = 0;
        for (int i = 0; i < 5; i++)
            offset |= (ulong)entry[i] << (8 * i);
        return new NapsFileOffsetEntry(entry[5], offset);
    }

    /// <summary>Encode a 6-byte fidx entry (inverse of <see cref="DecodeFileOffsetEntry"/>).</summary>
    public static byte[] EncodeFileOffsetEntry(NapsFileOffsetEntry entry)
    {
        var buffer = new byte[FileOffsetStride];
        ulong offset = entry.UncompressedOffsetStart;
        for (int i = 0; i < 5; i++)
            buffer[i] = (byte)(offset >> (8 * i));
        buffer[5] = entry.Type;
        return buffer;
    }

    /// <summary>Decode a 10-byte u2c entry (uint24 base + 7 delta bytes).</summary>
    public static NapsU2cEntry DecodeU2cEntry(ReadOnlySpan<byte> entry)
    {
        if (entry.Length < U2cStride)
            throw new ArgumentException($"u2c entry needs {U2cStride} bytes.", nameof(entry));

        uint baseOffset = (uint)(entry[0] | (entry[1] << 8) | (entry[2] << 16));
        var deltas = new byte[7];
        entry.Slice(3, 7).CopyTo(deltas);
        return new NapsU2cEntry(baseOffset, deltas);
    }

    /// <summary>Encode a 10-byte u2c entry (inverse of <see cref="DecodeU2cEntry"/>).</summary>
    public static byte[] EncodeU2cEntry(NapsU2cEntry entry)
    {
        var buffer = new byte[U2cStride];
        buffer[0] = (byte)entry.InfoOffset9BBase;
        buffer[1] = (byte)(entry.InfoOffset9BBase >> 8);
        buffer[2] = (byte)(entry.InfoOffset9BBase >> 16);
        for (int i = 0; i < 7 && i < entry.DeltaFromBase.Length; i++)
            buffer[3 + i] = entry.DeltaFromBase[i];
        return buffer;
    }

    /// <summary>
    /// Decode a 9-byte CblockInfo entry from its bit-packed fields.
    ///
    /// Each entry is a 72-bit little-endian value: bits 0–63 are the 8-byte LE word, bits 64–71
    /// are the 9th (high) byte. Bit positions are authoritative (FINDINGS.md §3.4b), extracted
    /// clean-room from Sony's <c>--print-layout</c> dumper:
    ///   STD: coffsetStartMod256K[0:18] isRunBase[18] (reserved)[19] uoffsetStart[20:38]
    ///        clenEvenMinus1[38:55] even[55:58] odd[58:61] KdePredictor[61:67] (reserved)[67]
    ///        shuffleIdx[68:72]
    ///   RUN: coffsetEndMod256K[0:18] isRunBase[18] (reserved)[19] tweakIdxStart[20:48]
    ///        keyTableIdx[48:50] coffsetStart256K[50:72]
    /// </summary>
    public static NapsCblockInfoEntry DecodeCblockInfoEntry(ReadOnlySpan<byte> entry)
    {
        if (entry.Length < CblockInfoStride)
            throw new ArgumentException($"cblockinfo entry needs {CblockInfoStride} bytes.", nameof(entry));

        var raw = new byte[CblockInfoStride];
        entry[..CblockInfoStride].CopyTo(raw);

        ulong lo = 0;
        for (int i = 0; i < 8; i++)
            lo |= (ulong)raw[i] << (8 * i);
        ulong hi = raw[8];

        bool isRunBase = ((lo >> 18) & 1) != 0;
        uint coffsetMod256K = (uint)(lo & 0x3FFFF);

        if (!isRunBase)
        {
            return new NapsCblockInfoEntry
            {
                Raw = raw,
                IsRunBase = false,
                CoffsetStartMod256K = coffsetMod256K,
                UoffsetStart = (uint)((lo >> 20) & 0x3FFFF),
                ClenEvenMinus1 = (uint)((lo >> 38) & 0x1FFFF),
                Even = (byte)((lo >> 55) & 0x7),
                Odd = (byte)((lo >> 58) & 0x7),
                KdePredictor = (byte)(((hi & 0x7) << 3) | ((lo >> 61) & 0x7)),
                ShuffleIdx = (byte)((hi >> 4) & 0xF),
            };
        }

        return new NapsCblockInfoEntry
        {
            Raw = raw,
            IsRunBase = true,
            CoffsetEndMod256K = coffsetMod256K,
            TweakIdxStart = (uint)((lo >> 20) & 0xFFFFFFF),
            KeyTableIdx = (byte)((lo >> 48) & 0x3),
            CoffsetStart256K = (uint)(((hi & 0xFF) << 14) | ((lo >> 50) & 0x3FFF)),
        };
    }

    /// <summary>Encode a CblockInfo entry from its model fields (inverse of <see cref="DecodeCblockInfoEntry"/>).</summary>
    public static byte[] EncodeCblockInfoEntry(NapsCblockInfoEntry entry)
    {
        ulong lo = (entry.IsRunBase ? entry.CoffsetEndMod256K : entry.CoffsetStartMod256K) & 0x3FFFF;
        ulong hi;
        if (!entry.IsRunBase)
        {
            lo |= (ulong)(entry.UoffsetStart & 0x3FFFF) << 20;
            lo |= (ulong)(entry.ClenEvenMinus1 & 0x1FFFF) << 38;
            lo |= (ulong)(entry.Even & 0x7) << 55;
            lo |= (ulong)(entry.Odd & 0x7) << 58;
            lo |= (ulong)(entry.KdePredictor & 0x7) << 61;
            hi = ((ulong)(entry.KdePredictor >> 3) & 0x7) | ((ulong)(entry.ShuffleIdx & 0xF) << 4);
        }
        else
        {
            lo |= 1UL << 18;
            lo |= (ulong)(entry.TweakIdxStart & 0xFFFFFFF) << 20;
            lo |= (ulong)(entry.KeyTableIdx & 0x3) << 48;
            lo |= (ulong)(entry.CoffsetStart256K & 0x3FFF) << 50;
            hi = (entry.CoffsetStart256K >> 14) & 0xFF;
        }

        // Preserve the two bits Sony's --print-layout dumper does not print but which are set
        // in real packages (semantics still unknown), so entries round-trip byte-exact:
        //   * bit 19 (both layouts) — between m_isRunBase and the next field.
        //   * byte-8 bit 3 == bit 67 (STD only) — between m_KdePredictor and m_shuffleIdx.
        //     (In RUN entries bit 67 is the upper part of m_coffsetStart256K, already modeled.)
        if (entry.Raw is { Length: CblockInfoStride })
        {
            lo |= (ulong)(uint)(entry.Raw[2] & 0x08) << 16;   // byte 2 bit 3 == bit 19 of lo
            if (!entry.IsRunBase)
                hi |= (ulong)(uint)(entry.Raw[8] & 0x08);      // byte 8 bit 3 == bit 67
        }

        var buffer = new byte[CblockInfoStride];
        for (int i = 0; i < 8; i++)
            buffer[i] = (byte)(lo >> (8 * i));
        buffer[8] = (byte)hi;
        return buffer;
    }

    /// <summary>Parse a full <c>naps_pkg_layout.dat</c> blob (counts decoded from the header).</summary>
    public static NapsLayoutDocument Parse(ReadOnlySpan<byte> blob)
    {
        NapsLayoutCounts counts = DecodeHeader(blob);
        return Parse(blob, counts);
    }

    /// <summary>Parse a full blob using explicitly supplied counts.</summary>
    public static NapsLayoutDocument Parse(ReadOnlySpan<byte> blob, NapsLayoutCounts counts)
    {
        NapsSectionMap map = SectionMap(counts);
        if (blob.Length < map.TotalSize)
            throw new ArgumentException(
                $"NAPS blob is {blob.Length} bytes but the counts require {map.TotalSize}.", nameof(blob));

        long alignedTotal = (map.TotalSize + 7) & ~7L;
        int trailingZeroBytes = blob.Length - (int)alignedTotal;
        for (int i = (int)alignedTotal; i < blob.Length; i++)
        {
            if (blob[i] != 0)
                throw new InvalidDataException("NAPS trailing footer contains non-zero bytes.");
        }

        var outerBlocks = SliceRaw(blob, map.OuterBlockDigest);
        var shuffles = SliceRaw(blob, map.ShufflePattern);

        var fileOffsets = new List<NapsFileOffsetEntry>(map.UncompressedOffsetStartByFileIdx.Count);
        for (int i = 0; i < map.UncompressedOffsetStartByFileIdx.Count; i++)
            fileOffsets.Add(DecodeFileOffsetEntry(EntrySpan(blob, map.UncompressedOffsetStartByFileIdx, i)));

        var u2c = new List<NapsU2cEntry>(map.CblockInfoOffsetByUblockIdxCompressed.Count);
        for (int i = 0; i < map.CblockInfoOffsetByUblockIdxCompressed.Count; i++)
            u2c.Add(DecodeU2cEntry(EntrySpan(blob, map.CblockInfoOffsetByUblockIdxCompressed, i)));

        var cblockInfos = new List<NapsCblockInfoEntry>(map.CblockInfo.Count);
        for (int i = 0; i < map.CblockInfo.Count; i++)
            cblockInfos.Add(DecodeCblockInfoEntry(EntrySpan(blob, map.CblockInfo, i)));

        return new NapsLayoutDocument
        {
            Counts = counts,
            Map = map,
            OuterBlockDigests = outerBlocks,
            ShufflePatterns = shuffles,
            FileOffsets = fileOffsets,
            CblockInfoOffsetByUblock = u2c,
            CblockInfos = cblockInfos,
            TrailingZeroBytes = trailingZeroBytes,
        };
    }

    /// <summary>
    /// Serialize a <see cref="NapsLayoutDocument"/> back into a blob
    /// (inverse of <see cref="Parse"/>), zero-padded to <paramref name="alignment"/>.
    /// </summary>
    public static byte[] BuildLayout(NapsLayoutDocument document, int alignment = DefaultAlignment)
    {
        ArgumentNullException.ThrowIfNull(document);
        NapsLayoutCounts counts = document.Counts;

        if (document.OuterBlockDigests.Count != counts.NumOuterBlocks)
            throw new ArgumentException($"OuterBlockDigests count {document.OuterBlockDigests.Count} != NumOuterBlocks {counts.NumOuterBlocks}.", nameof(document));
        if (document.ShufflePatterns.Count != counts.NumShufflePatterns)
            throw new ArgumentException($"ShufflePatterns count {document.ShufflePatterns.Count} != NumShufflePatterns {counts.NumShufflePatterns}.", nameof(document));
        if (document.FileOffsets.Count != counts.NumFiles)
            throw new ArgumentException($"FileOffsets count {document.FileOffsets.Count} != NumFiles {counts.NumFiles}.", nameof(document));
        if (document.CblockInfoOffsetByUblock.Count != counts.NumU2cEntries)
            throw new ArgumentException($"u2c count {document.CblockInfoOffsetByUblock.Count} != NumU2cEntries {counts.NumU2cEntries}.", nameof(document));
        if (document.CblockInfos.Count != counts.NumCblockInfo)
            throw new ArgumentException($"CblockInfos count {document.CblockInfos.Count} != NumCblockInfo {counts.NumCblockInfo}.", nameof(document));

        NapsSectionMap map = SectionMap(counts);
        long content = map.TotalSize;
        long total = document.TrailingZeroBytes >= 0
            ? ((content + 7) & ~7L) + document.TrailingZeroBytes
            : alignment > 1 ? (content + alignment - 1) / alignment * alignment : content;

        var blob = new byte[total];
        var span = blob.AsSpan();

        EncodeHeader(counts).CopyTo(span);

        for (int i = 0; i < document.OuterBlockDigests.Count; i++)
        {
            byte[] digest = document.OuterBlockDigests[i];
            if (digest.Length != OuterBlockDigestStride)
                throw new ArgumentException($"outer-block digest must be {OuterBlockDigestStride} bytes.", nameof(document));
            digest.CopyTo(span.Slice((int)map.OuterBlockDigest.Offset + i * OuterBlockDigestStride, OuterBlockDigestStride));
        }

        for (int i = 0; i < document.ShufflePatterns.Count; i++)
        {
            byte[] shuffle = document.ShufflePatterns[i];
            if (shuffle.Length != ShufflePatternStride)
                throw new ArgumentException($"shuffle pattern must be {ShufflePatternStride} bytes.", nameof(document));
            shuffle.CopyTo(span.Slice((int)map.ShufflePattern.Offset + i * ShufflePatternStride, ShufflePatternStride));
        }

        int pos = 0;
        foreach (NapsFileOffsetEntry entry in document.FileOffsets)
        {
            EncodeFileOffsetEntry(entry).CopyTo(span.Slice((int)map.UncompressedOffsetStartByFileIdx.Offset
                + pos * FileOffsetStride, FileOffsetStride));
            pos++;
        }

        pos = 0;
        foreach (NapsU2cEntry entry in document.CblockInfoOffsetByUblock)
        {
            EncodeU2cEntry(entry).CopyTo(span.Slice((int)map.CblockInfoOffsetByUblockIdxCompressed.Offset
                + pos * U2cStride, U2cStride));
            pos++;
        }

        pos = 0;
        foreach (NapsCblockInfoEntry entry in document.CblockInfos)
        {
            EncodeCblockInfoEntry(entry).CopyTo(span.Slice((int)map.CblockInfo.Offset
                + pos * CblockInfoStride, CblockInfoStride));
            pos++;
        }

        return blob;
    }

    private static ReadOnlySpan<byte> EntrySpan(ReadOnlySpan<byte> blob, NapsSection section, int index)
        => blob.Slice((int)section.Offset + index * section.Stride, section.Stride);

    private static List<byte[]> SliceRaw(ReadOnlySpan<byte> blob, NapsSection section)
    {
        var list = new List<byte[]>(section.Count);
        for (int i = 0; i < section.Count; i++)
        {
            var entry = new byte[section.Stride];
            blob.Slice((int)section.Offset + i * section.Stride, section.Stride).CopyTo(entry);
            list.Add(entry);
        }
        return list;
    }
}

/// <summary>Section counts of a <c>naps_pkg_layout.dat</c> structure.</summary>
public readonly record struct NapsLayoutCounts(
    int NumFiles,
    byte CompressionType,
    int NumKeys,
    int NumShufflePatterns,
    int NumUBlocks,
    int NumOuterBlocks,
    int NumCblockInfo)
{
    /// <summary>
    /// Number of 10-byte u2c entries: one per group of 8 uncompressed blocks, always rounded up
    /// with a trailing group (<c>floor(NumUBlocks/8)+1</c>). Confirmed byte-exact against the
    /// original tool at an exact multiple of 8 (24 ublocks emits 4 entries, not 3).
    /// </summary>
    public int NumU2cEntries => (NumUBlocks + 8) >> 3;

    /// <summary>Number of 6-byte fidx entries (includes the trailing mount-size sentinel).</summary>
    public int NumFileOffsetEntries => NumFiles;
}

/// <summary>Byte offset and size of one NAPS section.</summary>
public readonly record struct NapsSection(long Offset, long Size, int Stride, int Count);

/// <summary>Map of all NAPS sections in on-disk order.</summary>
public readonly record struct NapsSectionMap(
    NapsSection Header,
    NapsSection OuterBlockDigest,
    NapsSection ShufflePattern,
    NapsSection UncompressedOffsetStartByFileIdx,
    NapsSection CblockInfoOffsetByUblockIdxCompressed,
    NapsSection CblockInfo,
    long CblockInfoPad,
    long TotalSize);

/// <summary>A 6-byte fidx entry: 40-bit LE uncompressed offset + 1 type byte.</summary>
public readonly record struct NapsFileOffsetEntry(byte Type, ulong UncompressedOffsetStart);

/// <summary>A 10-byte u2c entry: uint24 base index + seven per-ublock delta bytes.</summary>
public readonly record struct NapsU2cEntry(uint InfoOffset9BBase, byte[] DeltaFromBase)
{
    /// <summary>Derived <c>start_cblockinfo_index</c> for each of the 8 blocks this entry covers.</summary>
    public IReadOnlyList<uint> StartCblockInfoIndex
    {
        get
        {
            var result = new uint[8];
            result[0] = InfoOffset9BBase;
            for (int i = 0; i < 7 && i < DeltaFromBase.Length; i++)
                result[i + 1] = InfoOffset9BBase + DeltaFromBase[i];
            return result;
        }
    }
}

/// <summary>
/// A 9-byte CblockInfo entry: run-base marker plus a per-block or run-anchor field set.
/// Field UNITS are BYTES (confirmed, FINDINGS.md §3.4b/§9.7):
///   CoffsetStartMod256K = compressed byte offset (mod 256K, 64K-aligned);
///   UoffsetStart = uncompressed byte offset (mod 256K);
///   ClenEvenMinus1 = even-chunk compressed size − 1 (bytes).
/// </summary>
public readonly record struct NapsCblockInfoEntry
{
    /// <summary>Raw 9 bytes, preserved verbatim.</summary>
    public byte[] Raw { get; init; }

    /// <summary>True for the run-base format, false for the per-block format.</summary>
    public bool IsRunBase { get; init; }

    // Per-block fields (valid when IsRunBase is false). All offsets/sizes are BYTES.
    public uint CoffsetStartMod256K { get; init; }
    public uint UoffsetStart { get; init; }
    public uint ClenEvenMinus1 { get; init; }

    /// <summary>3-bit even-block selector (bits 55–57).</summary>
    public byte Even { get; init; }

    /// <summary>3-bit odd-block selector (bits 58–60).</summary>
    public byte Odd { get; init; }

    /// <summary>6-bit KDE predictor selector (bits 61–66). Must be 0 for the reference/console decoder,
    /// which rejects any non-zero predictor; generated Kraken blocks therefore leave it 0.</summary>
    public byte KdePredictor { get; init; }

    /// <summary>4-bit shuffle selector (bits 68–71, top nibble of the high byte).</summary>
    public byte ShuffleIdx { get; init; }

    // Run-anchor fields (valid when IsRunBase is true).
    public uint CoffsetEndMod256K { get; init; }
    public uint TweakIdxStart { get; init; }
    public byte KeyTableIdx { get; init; }
    public uint CoffsetStart256K { get; init; }
}

/// <summary>A fully parsed <c>naps_pkg_layout.dat</c> blob.</summary>
public sealed class NapsLayoutDocument
{
    public required NapsLayoutCounts Counts { get; init; }
    public required NapsSectionMap Map { get; init; }
    public required IReadOnlyList<byte[]> OuterBlockDigests { get; init; }
    public required IReadOnlyList<byte[]> ShufflePatterns { get; init; }
    public required IReadOnlyList<NapsFileOffsetEntry> FileOffsets { get; init; }
    public required IReadOnlyList<NapsU2cEntry> CblockInfoOffsetByUblock { get; init; }
    public required IReadOnlyList<NapsCblockInfoEntry> CblockInfos { get; init; }

    /// <summary>
    /// All-zero footer size observed when this document was parsed. The native writer emits
    /// <c>align8(CblockInfoEnd) + footer</c>; the footer is package-dependent (0 for the debug
    /// base package, 8 for nwonly packages, 12 for the retail sample). A negative value means the
    /// document was not parsed and <see cref="ProsperoNapsLayout.BuildLayout"/> falls back to the
    /// caller's alignment.
    /// </summary>
    public int TrailingZeroBytes { get; init; } = -1;
}
