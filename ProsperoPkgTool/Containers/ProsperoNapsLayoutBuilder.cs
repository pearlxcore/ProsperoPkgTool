using System.Buffers.Binary;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room generator for the PS5 <c>naps_pkg_layout.dat</c> streaming layout
/// (FINDINGS.md §5, §9.7). It walks an inner-image block plan with a compressed-offset cursor and
/// emits the CblockInfo / u2c / fidx / header sections that
/// <see cref="ProsperoNapsLayout.BuildLayout"/> serializes.
///
/// All offsets and lengths are BYTES (the Sony-native units, confirmed byte-exact against the debug
/// and retail packages). This corrects the reference builder's factor-of-2 halfword math and its
/// phase-shifted <c>BuildU2c</c>.
///
/// The block plan (<see cref="NapsCblockPlanEntry"/>) encodes, per STD block, its compressed and
/// uncompressed geometry plus the compressor's per-block flags (<c>even</c>/<c>odd</c>/<c>kde</c>/
/// <c>shuffle</c>). A block may open a new RUN base (<see cref="NapsCblockPlanEntry.StartRun"/>),
/// which re-bases the compressed-offset cursor; the run schedule is a compressor artifact and is
/// supplied by the caller rather than derived here.
/// </summary>
public static class ProsperoNapsLayoutBuilder
{
    private const long UBlock = 0x40000;   // 256 KiB uncompressed block
    private const long Mod256K = 0x3FFFF;  // 18-bit mod-0x40000 mask
    private const long ClenEvenCap = 0x1FFFF; // capped clenEvenMinus1 (full 128 KiB chunk)

    /// <summary>
    /// Generate the full <see cref="NapsLayoutDocument"/> from an inner-image block plan. The result
    /// serializes via <see cref="ProsperoNapsLayout.BuildLayout"/>.
    /// </summary>
    public static NapsLayoutDocument BuildDocument(NapsGenerationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Blocks is null || request.Blocks.Count == 0)
            throw new ArgumentException("A naps generation request needs at least one block.", nameof(request));
        if (request.FileLogicalOffsets is null || request.FileLogicalOffsets.Count == 0)
            throw new ArgumentException("A naps generation request needs the fidx logical-offset table.", nameof(request));
        ValidateRequest(request);

        (List<NapsCblockInfoEntry> cblockInfos, List<(int Index, long Logical)> stdLogical) = WalkBlocks(request.Blocks);

        var counts = new NapsLayoutCounts(
            NumFiles: request.FileLogicalOffsets.Count,
            CompressionType: request.CompressionType,
            NumKeys: request.NumKeys,
            NumShufflePatterns: request.ShufflePatterns?.Count ?? 0,
            NumUBlocks: request.NumUBlocks,
            NumOuterBlocks: request.NumOuterBlocks,
            NumCblockInfo: cblockInfos.Count);

        List<NapsFileOffsetEntry> fileOffsets = BuildFileOffsets(request);
        List<NapsU2cEntry> u2c = BuildU2c(stdLogical, counts.NumUBlocks, counts.NumCblockInfo);

        IReadOnlyList<byte[]> outerDigests = request.OuterBlockDigests
            ?? Enumerable.Range(0, request.NumOuterBlocks)
                         .Select(_ => new byte[ProsperoNapsLayout.OuterBlockDigestStride])
                         .ToList();
        IReadOnlyList<byte[]> shuffles = request.ShufflePatterns ?? Array.Empty<byte[]>();

        return new NapsLayoutDocument
        {
            Counts = counts,
            Map = ProsperoNapsLayout.SectionMap(counts),
            OuterBlockDigests = outerDigests,
            ShufflePatterns = shuffles,
            FileOffsets = fileOffsets,
            CblockInfoOffsetByUblock = u2c,
            CblockInfos = cblockInfos,
        };
    }

    /// <summary>Generate and serialize a <c>naps_pkg_layout.dat</c> blob from a block plan.</summary>
    public static byte[] Build(NapsGenerationRequest request, int alignment = ProsperoNapsLayout.DefaultAlignment)
        => ProsperoNapsLayout.BuildLayout(BuildDocument(request), alignment);

    private static void ValidateRequest(NapsGenerationRequest request)
    {
        if (request.NumUBlocks <= 0 || request.NumOuterBlocks < 0)
            throw new ArgumentOutOfRangeException(nameof(request), "NAPS block counts must be non-negative and include at least one ublock.");
        if (request.OuterBlockDigests is { Count: var digests } && digests != request.NumOuterBlocks)
            throw new ArgumentException("Outer digest table length must equal NumOuterBlocks.", nameof(request));
        if (request.ShufflePatterns is { Count: > 15 })
            throw new ArgumentException("NAPS supports at most 15 shuffle patterns.", nameof(request));
        for (int i = 0; i < request.FileLogicalOffsets.Count; i++)
        {
            if (request.FileLogicalOffsets[i] < 0)
                throw new ArgumentException(
                    $"fidx logical offset {i}/{request.FileLogicalOffsets.Count} is negative ({request.FileLogicalOffsets[i]}).", nameof(request));
            if (i > 0 && request.FileLogicalOffsets[i] < request.FileLogicalOffsets[i - 1])
                throw new ArgumentException(
                    $"fidx logical offset {i}/{request.FileLogicalOffsets.Count} ({request.FileLogicalOffsets[i]}) is less than offset {i - 1} ({request.FileLogicalOffsets[i - 1]}).", nameof(request));
        }
        int terminators = request.Blocks.Count(b => b.Terminator);
        if (terminators != 1 || !request.Blocks[^1].Terminator)
            throw new ArgumentException("A NAPS plan must end with exactly one terminator.", nameof(request));
        for (int i = 0; i < request.Blocks.Count; i++)
        {
            NapsCblockPlanEntry b = request.Blocks[i];
            if (b.OnDiskOffset < 0 || b.LogicalOffset < 0 || b.StreamLength < 0 || b.EvenChunkCompressedLength < 0)
                throw new ArgumentException($"NAPS block {i} has a negative offset or length.", nameof(request));
            bool zeroHole = !b.Terminator && b.StreamLength == 0 && b.EvenChunkCompressedLength == 0 &&
                b.Even == 0 && b.Odd == 0 && b.KdePredictor == 0;
            if (!b.Terminator && !zeroHole && !b.IsAlias && (b.StreamLength <= 0 || b.StreamLength > UBlock || b.EvenChunkCompressedLength <= 0 || b.EvenChunkCompressedLength > 0x20000))
                throw new ArgumentException($"NAPS block {i} has an unsupported stored stream geometry.", nameof(request));
            if (!b.Terminator && b.LogicalOffset + UBlock < b.LogicalOffset)
                throw new ArgumentException($"NAPS block {i} logical range overflows.", nameof(request));
        }
    }

    /// <summary>
    /// Walk the block plan with a compressed-offset cursor and emit CblockInfo entries. A RUN base
    /// re-bases the cursor from the block's on-disk offset; a STD entry records the cursor's low
    /// 18 bits and advances the cursor by the block's stream length.
    ///
    /// Byte-unit field semantics (verified against ground truth):
    ///   RUN:  <c>CoffsetEndMod256K = cursor &amp; 0x3FFFF</c> (before reset),
    ///         <c>TweakIdxStart = onDisk &gt;&gt; 16</c>, <c>CoffsetStart256K = onDisk &gt;&gt; 18</c>,
    ///         then cursor resets to <c>onDisk</c> (the block's absolute on-disk byte offset).
    ///   STD:  <c>CoffsetStartMod256K = cursor &amp; 0x3FFFF</c>,
    ///         <c>UoffsetStart = logical &amp; 0x3FFFF</c>,
    ///         <c>ClenEvenMinus1 = min(evenComp - 1, 0x1FFFF)</c>, then cursor += streamLength.
    ///   The terminator is special: <c>ClenEvenMinus1 = 0</c>, bit 19 set (last-block marker).
    /// </summary>
    private static (List<NapsCblockInfoEntry> Entries, List<(int Index, long Logical)> StdLogical) WalkBlocks(
        IReadOnlyList<NapsCblockPlanEntry> blocks)
    {
        var entries = new List<NapsCblockInfoEntry>(blocks.Count * 2);
        var stdLogical = new List<(int, long)>(blocks.Count);
        long cursor = 0;

        foreach (NapsCblockPlanEntry blk in blocks)
        {
            if (blk.StartRun)
            {
                uint coffEnd = (uint)(cursor & Mod256K);
                uint tweak = blk.Terminator ? 0u : (uint)(blk.OnDiskOffset >> 16);
                uint c256K = (uint)(blk.OnDiskOffset >> 18);
                entries.Add(new NapsCblockInfoEntry
                {
                    Raw = new byte[ProsperoNapsLayout.CblockInfoStride],
                    IsRunBase = true,
                    CoffsetEndMod256K = coffEnd,
                    TweakIdxStart = tweak,
                    KeyTableIdx = 0,
                    CoffsetStart256K = c256K,
                });
                cursor = blk.OnDiskOffset; // re-base the cursor to the block's absolute on-disk offset
            }

            uint coffMod = (uint)(cursor & Mod256K);

            // The terminator is a sentinel STD block: its uoffset is the mount size (mod 256K), its
            // even-chunk length is 0, and bit 19 is set (the "last block" marker; see FINDINGS.md §3.4b).
            byte[] raw = new byte[ProsperoNapsLayout.CblockInfoStride];
            uint uoff;
            uint clenEvenMinus1;
            if (blk.Terminator)
            {
                uoff = (uint)(blk.LogicalOffset & Mod256K);
                clenEvenMinus1 = 0;
                raw[2] |= 0x08; // bit 19 (lo byte 2 bit 3) — carried through by EncodeCblockInfoEntry.
            }
            else
            {
                uoff = (uint)(blk.LogicalOffset & Mod256K);
                clenEvenMinus1 = (uint)Math.Min(blk.EvenChunkCompressedLength - 1, ClenEvenCap);
                if (blk.StoredRaw)
                    raw[8] |= 0x08; // clean-room stored-only marker in the otherwise unprinted bit 67
            }

            int stdIndex = entries.Count;
            entries.Add(new NapsCblockInfoEntry
            {
                Raw = raw,
                IsRunBase = false,
                CoffsetStartMod256K = coffMod,
                UoffsetStart = uoff,
                ClenEvenMinus1 = clenEvenMinus1,
                Even = blk.Even,
                Odd = blk.Odd,
                KdePredictor = blk.KdePredictor,
                ShuffleIdx = blk.ShuffleIndex,
            });
            stdLogical.Add((stdIndex, blk.LogicalOffset));

            cursor += blk.StreamLength;
        }

        return (entries, stdLogical);
    }

    /// <summary>
    /// Build the fidx entries from the afid-order logical-offset table. The final entry is the total
    /// inner logical size and carries <see cref="NapsGenerationRequest.FinalFileOffsetType"/>.
    /// </summary>
    private static List<NapsFileOffsetEntry> BuildFileOffsets(NapsGenerationRequest request)
    {
        int fileCount = request.FileLogicalOffsets.Count;
        var list = new List<NapsFileOffsetEntry>(fileCount);
        for (int i = 0; i < fileCount; i++)
        {
            byte type = (i == fileCount - 1) ? request.FinalFileOffsetType : (byte)0;
            list.Add(new NapsFileOffsetEntry(type, (ulong)request.FileLogicalOffsets[i]));
        }
        return list;
    }

    /// <summary>
    /// Build the u2c (compressed-offset acceleration) table using the Sony-native encoding
    /// (FINDINGS.md §9.7, verified byte-exact): each 10-byte entry is
    /// <c>{ uint24 LE base, byte delta[7] }</c> covering ublocks <c>8g..8g+7</c>, where
    /// <c>start[8g] = base</c> and <c>start[8g+1+i] = base + delta[i]</c> for <c>i</c> in 0..6.
    /// <c>start[u]</c> is the index of the first STD block whose logical start is &gt;= <c>u·0x40000</c>;
    /// ublocks beyond the last real block clamp to the terminator index.
    /// </summary>
    private static List<NapsU2cEntry> BuildU2c(
        List<(int Index, long Logical)> stdLogical, int numUBlocks, int numCblockInfo)
    {
        (int Index, long Logical)[] sorted = stdLogical.OrderBy(t => t.Logical).ToArray();

        // first[u] = index of the first STD whose logical start >= u*0x40000 (monotonic linear pass).
        int[] first = new int[numUBlocks];
        int p = 0;
        for (int u = 0; u < numUBlocks; u++)
        {
            long target = (long)u * UBlock;
            while (p < sorted.Length && sorted[p].Logical < target)
                p++;
            first[u] = p < sorted.Length ? sorted[p].Index : numCblockInfo - 1;
        }

        static byte ToU2cByte(int value, string field) => value is >= 0 and <= 255
            ? (byte)value
            : throw new NotSupportedException(
                $"NAPS u2c {field} value {value} exceeds the single-byte delta field; this layout size is unsupported.");

        int numGroups = (numUBlocks + 8) / 8;
        var u2c = new List<NapsU2cEntry>(numGroups);
        for (int g = 0; g < numGroups; g++)
        {
            int baseU = 8 * g;
            int baseIndex = baseU < numUBlocks ? first[baseU] : numCblockInfo - 1;

            var deltas = new byte[7];
            for (int i = 0; i < 7; i++)
            {
                int u = baseU + 1 + i;
                int start = u < numUBlocks ? first[u] : numCblockInfo - 1;
                deltas[i] = ToU2cByte(start - baseIndex, "delta");
            }

            u2c.Add(new NapsU2cEntry((uint)baseIndex, deltas));
        }

        return u2c;
    }
}

/// <summary>
/// One logical block in the NAPS generation plan. Each entry becomes one STD (per-block) CblockInfo
/// record, optionally preceded by a RUN base record when <see cref="StartRun"/> is set. All
/// offsets/lengths are BYTES.
/// </summary>
public sealed class NapsCblockPlanEntry
{
    /// <summary>Zero-stream alias of an earlier block at the same source offset.</summary>
    public bool IsAlias { get; init; }
    /// <summary>Marks a stored-only block emitted by this clean-room writer. The bit is reserved in
    /// fixture observations and lets the reader distinguish a 256KiB raw modulo wrap from a dedup alias.</summary>
    public bool StoredRaw { get; init; }
    /// <summary>Emit a RUN-base CblockInfo record before this block (re-bases the compressed-offset space).</summary>
    public bool StartRun { get; init; }

    /// <summary>The block's on-disk (compressed-image) byte offset. Only used when <see cref="StartRun"/> is set.</summary>
    public long OnDiskOffset { get; init; }

    /// <summary>The block's uncompressed logical start offset (drives <c>UoffsetStart</c> and the u2c map).</summary>
    public long LogicalOffset { get; init; }

    /// <summary>Compressed length of the block's even (or sole) chunk, in bytes (drives <c>ClenEvenMinus1</c>).</summary>
    public long EvenChunkCompressedLength { get; init; }

    /// <summary>Bytes the compressed-offset cursor advances after this block (total on-disk stream length).</summary>
    public long StreamLength { get; init; }

    /// <summary>3-bit even-chunk selector (bits 55–57). Semantics still under investigation; caller-supplied.</summary>
    public byte Even { get; init; }

    /// <summary>3-bit odd-chunk selector (bits 58–60). Semantics still under investigation; caller-supplied.</summary>
    public byte Odd { get; init; }

    /// <summary>6-bit KDE predictor selector (bits 61–66). Must be 0 for the reference/console decoder,
    /// which rejects any non-zero predictor.</summary>
    public byte KdePredictor { get; init; }

    /// <summary>4-bit shuffle selector (bits 68–71).</summary>
    public byte ShuffleIndex { get; init; }

    /// <summary>True for the single trailing terminator block (cursor is not re-based from its offset).</summary>
    public bool Terminator { get; init; }
}

/// <summary>Inputs for generating a <c>naps_pkg_layout.dat</c> from a built inner image.</summary>
public sealed class NapsGenerationRequest
{
    /// <summary>Compression type (2 = Kraken for the nwonly format; 0 = stored).</summary>
    public byte CompressionType { get; init; } = 0;

    /// <summary>Number of 256 KiB uncompressed blocks: <c>ceil(totalLogicalSize / 0x40000)</c>.</summary>
    public required int NumUBlocks { get; init; }

    /// <summary>Number of on-disk outer blocks in the built image (superblock block count).</summary>
    public required int NumOuterBlocks { get; init; }

    /// <summary>Number of distinct keys (1 for the debug format).</summary>
    public int NumKeys { get; init; } = 1;

    /// <summary>The afid-order uncompressed logical start offsets (the fidx offsets). The final entry is the
    /// total inner logical size and is emitted with <see cref="FinalFileOffsetType"/>.</summary>
    public required IReadOnlyList<long> FileLogicalOffsets { get; init; }

    /// <summary>Type byte for the final (total-size) fidx entry.</summary>
    public byte FinalFileOffsetType { get; init; } = 0x40;

    /// <summary>The ordered block plan.</summary>
    public required IReadOnlyList<NapsCblockPlanEntry> Blocks { get; init; }

    /// <summary>Optional explicit 8-byte outer-block digest entries. Defaults to all-zero entries.</summary>
    public IReadOnlyList<byte[]>? OuterBlockDigests { get; init; }

    /// <summary>Optional 8-byte shuffle-pattern entries (defaults to none).</summary>
    public IReadOnlyList<byte[]>? ShufflePatterns { get; init; }
}
