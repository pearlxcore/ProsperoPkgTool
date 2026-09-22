using Block = ProsperoPkgTool.Containers.ProsperoPs5InnerImageReader.InnerBlock;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Reader for the sparse-fidx layout Sony's own writer produces for the PS3-emulation packages.
///
/// Two properties separate it from every layout the established dialects handle, and both are
/// required before this dialect will decode anything:
///
///   * fidx carries one or more non-sentinel entries marked 0x40 (the sentinel uses the same
///     marker). Each marks the start of a whole 256 KiB sparse page that is absent from the STD
///     stream, so the walk's logical coverage falls short of the sentinel by whole pages.
///   * A stored span that fills a whole 256 KiB block advances the compressed cursor by exactly
///     one page, so its 18-bit coffset delta wraps to zero. The plain traversals read that as a
///     dedup alias with no source; here the wrapped delta plus a full even sub-chunk identifies
///     the span instead, which is why these packages decode only through this reader.
///
/// This dialect is registered as a last resort: it is only consulted after compatible-coffset-v1,
/// native-span-v1 and indexed-coffset-v1 have all declined, so every package that reads today
/// keeps the exact dialect and the exact bytes it produced before this reader existed. Both
/// checks below also make the reader decline on its own evidence, independently of that ordering.
/// </summary>
internal sealed class NapsSparseFidxDialect : INapsDialect
{
    private const int PageSize = 0x40000;
    private const int Chunk128K = 0x20000;
    private const uint Mod256K = 0x3FFFF;
    private const byte SparseMarker = 0x40;

    public string Id => "sparse-fidx-v1";

    public IReadOnlyList<Block> Decode(ReadOnlySpan<byte> naps, long sourceLength)
    {
        try
        {
            return DecodeCore(naps, sourceLength);
        }
        catch (ArgumentException ex)
        {
            // A blob too short for the sections its own header declares is not a layout this reader
            // can speak for. Report it as a decline so the registry records the reason next to the
            // other dialects instead of letting an argument error escape the selection.
            throw new InvalidDataException($"Sparse-fidx layout rejected: {ex.Message}", ex);
        }
    }

    private IReadOnlyList<Block> DecodeCore(ReadOnlySpan<byte> naps, long sourceLength)
    {
        NapsLayoutDocument doc = ProsperoNapsLayout.Parse(naps);

        int sparseMarkers = 0;
        for (int i = 0; i + 1 < doc.FileOffsets.Count; i++)
        {
            if (doc.FileOffsets[i].Type == SparseMarker) sparseMarkers++;
        }
        if (sparseMarkers == 0)
            throw new InvalidDataException(
                "Sparse-fidx layout requires a non-sentinel fidx entry carrying the 0x40 sparse marker.");

        if (NapsIndexedLogicalMap.ReadMountEnd(naps) is not { } declaredEnd)
            throw new InvalidDataException("Sparse-fidx layout requires an exact fidx mount sentinel.");

        IReadOnlyList<Block> blocks = WalkUnmarkedStoredSpans(naps, sourceLength);
        long walkedEnd = blocks[^1].UncompressedOffset + blocks[^1].UncompressedLength;
        if (declaredEnd <= walkedEnd || (declaredEnd - walkedEnd) % PageSize != 0)
            throw new InvalidDataException(
                "Sparse-fidx layout requires whole missing logical pages between the walk and the mount end.");

        return RestoreSparsePages(doc, blocks, walkedEnd, declaredEnd);
    }

    /// <summary>
    /// Walk the CblockInfo section for a reference-writer data-first layout. A full 256 KiB stored
    /// span that omits the clean-room stored marker is accepted by its wrapped delta, a native
    /// zero-hole span steps the compressed cursor past its 8/16-byte payload, and every span must
    /// prove its source range lies inside the image before it is trusted.
    /// </summary>
    private static List<Block> WalkUnmarkedStoredSpans(ReadOnlySpan<byte> naps, long imageLength)
    {
        IReadOnlyList<NapsCblockInfoEntry> cb = DecodeCblockInfos(naps);

        var stds = new List<(NapsCblockInfoEntry Entry, NapsCblockInfoEntry? Run, int RunIndex, int EntryIndex, uint EndCoffMod)>();
        NapsCblockInfoEntry? activeRun = null;
        int runIndex = -1;
        for (int i = 0; i < cb.Count; i++)
        {
            if (cb[i].IsRunBase) { activeRun = cb[i]; runIndex = i; continue; }
            uint endCoffMod = i + 1 < cb.Count
                ? (cb[i + 1].IsRunBase ? cb[i + 1].CoffsetEndMod256K : cb[i + 1].CoffsetStartMod256K)
                : cb[i].CoffsetStartMod256K;
            stds.Add((cb[i], activeRun, runIndex, i, endCoffMod));
        }
        if (stds.Count < 2)
            throw new InvalidDataException("NAPS CblockInfo does not contain a STD block and terminator.");

        var result = new List<Block>(stds.Count - 1);
        long absUoff = 0;
        long sourceCursor = 0;
        int lastRun = -1;
        var sourceOwners = new Dictionary<long, int>();
        for (int i = 0; i + 1 < stds.Count; i++)
        {
            NapsCblockInfoEntry curr = stds[i].Entry;
            NapsCblockInfoEntry next = stds[i + 1].Entry;

            if (stds[i].Run is { } run && stds[i].RunIndex != lastRun)
            {
                // A RUN records the absolute 256 KiB page; the following STD supplies its low 18 bits.
                sourceCursor = ((long)run.CoffsetStart256K << 18) | curr.CoffsetStartMod256K;
                lastRun = stds[i].RunIndex;
            }

            int uncompressed = (int)((uint)((next.UoffsetStart - curr.UoffsetStart - 1) & Mod256K) + 1);
            int totalComp = (int)((stds[i].EndCoffMod - curr.CoffsetStartMod256K) & Mod256K);
            int evenComp = (int)(curr.ClenEvenMinus1 + 1);

            bool zeroHole = (curr.Even == 0 && curr.Odd == 0 && curr.KdePredictor == 0)
                || (curr.Even == 1 && curr.KdePredictor == 0 && curr.ClenEvenMinus1 == 7 &&
                    ((curr.Odd == 1 && totalComp == 16 && uncompressed > 16) ||
                     (curr.Odd == 0 && totalComp == 8 && uncompressed > 8)));
            bool stored = (curr.Raw[8] & 0x08) != 0 && !zeroHole;
            if (!zeroHole && curr.Even == 1 &&
                curr.Odd == (uncompressed > Chunk128K ? 1 : 0) &&
                evenComp == Math.Min(uncompressed, Chunk128K) &&
                totalComp == (uncompressed & (int)Mod256K))
            {
                stored = true;
            }
            if (stored) totalComp = uncompressed;
            bool isDedup = !stored && !zeroHole && totalComp == 0;
            bool kraken = !stored && !isDedup && !zeroHole && totalComp < uncompressed;

            if (!zeroHole && !isDedup && (sourceCursor < 0 || sourceCursor > imageLength ||
                totalComp > imageLength - sourceCursor))
                throw new InvalidDataException($"NAPS source outside image at record {stds[i].EntryIndex}.");
            if (!zeroHole && !isDedup && !stored && !kraken)
                throw new InvalidDataException($"Invalid NAPS span at record {stds[i].EntryIndex}.");
            if (kraken && (totalComp <= 0 || evenComp > totalComp ||
                (uncompressed > Chunk128K && evenComp == totalComp)))
                throw new InvalidDataException($"Invalid compressed range at record {stds[i].EntryIndex}.");

            int owner = -1;
            if (isDedup)
            {
                if (!sourceOwners.TryGetValue(sourceCursor, out owner) || owner < 0 || owner >= result.Count ||
                    result[owner].CompressedOffset != sourceCursor)
                    throw new InvalidDataException(
                        $"NAPS dedup alias at logical 0x{absUoff:X} references compressed offset 0x{sourceCursor:X} with no matching source block.");
            }

            int krakenFlags = kraken ? DeriveKrakenFlags(curr.Even, curr.Odd, uncompressed > Chunk128K) : 0;
            result.Add(new Block(sourceCursor, totalComp, evenComp, absUoff, uncompressed, kraken,
                zeroHole, isDedup, owner, lastRun, krakenFlags));

            // A native zero-hole span still occupies its 8/16-byte payload in the compressed stream,
            // so the cursor must step past it; only the legacy marker form carries no payload.
            bool advances = (!zeroHole || (curr.Even == 1 && curr.ClenEvenMinus1 == 7)) && !isDedup;
            if (!zeroHole && !isDedup) sourceOwners[sourceCursor] = result.Count - 1;
            absUoff += uncompressed;
            if (advances) sourceCursor += totalComp;
        }
        return result;
    }

    /// <summary>
    /// Insert the whole sparse pages the fidx markers declare. The u2c acceleration table supplies
    /// each page's absolute logical position, and every fidx entry is then checked against the
    /// restored boundaries: a payload entry must start a payload span, a sparse-marked entry must
    /// start a restored hole, and the trailing sentinel must equal the restored coverage.
    /// </summary>
    private static List<Block> RestoreSparsePages(NapsLayoutDocument doc, IReadOnlyList<Block> blocks,
        long walkedEnd, long declaredEnd)
    {
        var stds = doc.CblockInfos.Select((entry, index) => (Entry: entry, Index: index))
            .Where(item => !item.Entry.IsRunBase).ToArray();
        if (stds.Length != blocks.Count + 1)
            throw new InvalidDataException("Sparse-fidx layout requires one STD per payload block and a terminator.");
        if (declaredEnd <= (doc.Counts.NumUBlocks - 1L) * PageSize || declaredEnd > (long)doc.Counts.NumUBlocks * PageSize)
            throw new InvalidDataException("Sparse-fidx mount end disagrees with the header ublock count.");

        var anchors = new Dictionary<int, long>();
        var pageIndices = new int[doc.Counts.NumUBlocks];
        int previousIndex = -1;
        for (int page = 0; page < pageIndices.Length; page++)
        {
            var group = doc.CblockInfoOffsetByUblock[page / 8];
            long index = group.InfoOffset9BBase + (page % 8 == 0 ? 0L : group.DeltaFromBase[page % 8 - 1]);
            if (index < previousIndex || index >= doc.CblockInfos.Count || doc.CblockInfos[(int)index].IsRunBase)
                throw new InvalidDataException($"Invalid NAPS u2c STD anchor for logical page {page}.");
            previousIndex = pageIndices[page] = (int)index;
            anchors[(int)index] = (long)page * PageSize;
        }

        var restored = new List<Block>(blocks.Count);
        var starts = new long[stds.Length];
        var sourceIndices = new int[blocks.Count];
        long shift = 0;
        for (int i = 0; i < stds.Length; i++)
        {
            long original = i < blocks.Count ? blocks[i].UncompressedOffset : walkedEnd;
            long logical = checked(original + shift);
            if (anchors.TryGetValue(stds[i].Index, out long minimum) && logical < minimum)
            {
                long gap = ((minimum - logical + PageSize - 1) / PageSize) * PageSize;
                if (gap > declaredEnd - walkedEnd - shift)
                    throw new InvalidDataException("NAPS u2c anchors demand more sparse pages than the fidx mount allows.");
                for (long added = 0; added < gap; added += PageSize)
                    restored.Add(new Block(0, 0, 0, logical + added, PageSize, false, IsZeroHole: true));
                shift += gap;
                logical += gap;
            }
            if ((logical & (PageSize - 1)) != stds[i].Entry.UoffsetStart)
                throw new InvalidDataException($"NAPS sparse logical offset disagrees with STD {stds[i].Index}.");
            starts[i] = logical;
            if (i == blocks.Count) break;
            Block block = blocks[i];
            int owner = block.SourceBlockIndex;
            if (block.IsAlias && owner >= 0)
            {
                if (owner >= i) throw new InvalidDataException("Sparse-fidx alias must reference an earlier payload block.");
                owner = sourceIndices[owner];
            }
            sourceIndices[i] = restored.Count;
            restored.Add(block with { UncompressedOffset = logical, SourceBlockIndex = owner });
        }
        if (starts[^1] != declaredEnd)
            throw new InvalidDataException("NAPS sparse logical coverage does not reach the exact fidx mount end.");

        // Check the entire acceleration table, not only the entries that introduced gaps.
        int firstStd = 0;
        for (int page = 0; page < pageIndices.Length; page++)
        {
            while (firstStd + 1 < starts.Length && starts[firstStd] < (long)page * PageSize) firstStd++;
            if (stds[firstStd].Index != pageIndices[page])
                throw new InvalidDataException($"NAPS u2c page {page} disagrees with the restored STD boundaries.");
        }

        var payloadStarts = starts.ToHashSet();
        var holeStarts = new HashSet<long>();
        foreach (Block block in restored)
        {
            if (block.IsZeroHole) holeStarts.Add(block.UncompressedOffset);
        }
        ulong previousOffset = 0;
        for (int i = 0; i + 1 < doc.FileOffsets.Count; i++)
        {
            NapsFileOffsetEntry file = doc.FileOffsets[i];
            long offset = (long)file.UncompressedOffsetStart;
            bool isBoundary = file.Type == SparseMarker
                ? holeStarts.Contains(offset)
                : payloadStarts.Contains(offset);
            if (file.UncompressedOffsetStart < previousOffset ||
                file.UncompressedOffsetStart > (ulong)declaredEnd || !isBoundary)
                throw new InvalidDataException("NAPS fidx entry disagrees with the restored logical block boundaries.");
            previousOffset = file.UncompressedOffsetStart;
        }
        return restored;
    }

    private static IReadOnlyList<NapsCblockInfoEntry> DecodeCblockInfos(ReadOnlySpan<byte> naps)
    {
        NapsLayoutCounts counts = ProsperoNapsLayout.DecodeHeader(naps);
        long cbiBase = ProsperoNapsLayout.ComputeCblockInfoBase(naps);
        int count = counts.NumCblockInfo;
        if (cbiBase < 0 || cbiBase > naps.Length || (long)count * 9 > naps.Length - cbiBase)
            throw new InvalidDataException($"Truncated NAPS CblockInfo table: declared {count} records at 0x{cbiBase:X}.");

        var entries = new List<NapsCblockInfoEntry>(count);
        for (int i = 0; i < count; i++)
        {
            long byteOffset = cbiBase + (long)i * 72 / 8;
            if (byteOffset + 9 > naps.Length)
                throw new InvalidDataException($"Truncated NAPS CblockInfo record {i} of {count}.");
            entries.Add(ProsperoNapsLayout.DecodeCblockInfoEntry(naps.Slice((int)byteOffset, 9)));
        }
        return entries;
    }

    /// <summary>
    /// Inverse of the writer's Even/Odd selector mapping: the even selector carries the first
    /// sub-chunk's newLZ (bit 2) and delta-literal (bit 1) mode, the odd selector the same for the
    /// second sub-chunk.
    /// </summary>
    private static int DeriveKrakenFlags(byte even, byte odd, bool multiChunk)
    {
        int flags = 0;
        if ((even & 4) != 0) flags |= 0x02;
        if ((even & 2) != 0) flags |= 0x01;
        if (multiChunk)
        {
            if ((odd & 4) != 0) flags |= 0x20;
            if ((odd & 2) != 0) flags |= 0x10;
        }
        return flags;
    }
}
