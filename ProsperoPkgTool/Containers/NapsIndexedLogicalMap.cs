using Block = ProsperoPkgTool.Containers.ProsperoPs5InnerImageReader.InnerBlock;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Restores whole-page sparse slots omitted from the STD stream. STD logical offsets retain
/// only 18 bits, so an inter-file 256 KiB gap is invisible to consecutive-STD delta arithmetic.
/// The u2c acceleration table supplies absolute page anchors; fidx independently checks the
/// resulting file boundaries and exact mount end. Payload block lengths are never inflated.
/// </summary>
internal static class NapsIndexedLogicalMap
{
    private const int PageSize = 0x40000;

    internal static long? ReadMountEnd(ReadOnlySpan<byte> naps)
    {
        var counts = ProsperoNapsLayout.DecodeHeader(naps);
        var section = ProsperoNapsLayout.SectionMap(counts).UncompressedOffsetStartByFileIdx;
        long offset = section.Offset + (counts.NumFiles - 1L) * ProsperoNapsLayout.FileOffsetStride;
        if (offset < 0 || offset > naps.Length - ProsperoNapsLayout.FileOffsetStride)
            throw new InvalidDataException("NAPS fidx mount sentinel lies outside the layout.");
        var sentinel = ProsperoNapsLayout.DecodeFileOffsetEntry(naps.Slice((int)offset, ProsperoNapsLayout.FileOffsetStride));
        return sentinel.Type == 0x40 ? checked((long)sentinel.UncompressedOffsetStart) : null;
    }

    internal static IReadOnlyList<Block> Restore(ReadOnlySpan<byte> naps, IReadOnlyList<Block> blocks)
    {
        long walkedEnd = blocks[^1].UncompressedOffset + blocks[^1].UncompressedLength;
        long declaredEnd = ReadMountEnd(naps) ?? 0;
        if (declaredEnd <= walkedEnd ||
            (declaredEnd - walkedEnd) % PageSize != 0)
            throw new InvalidDataException("Indexed NAPS map requires an exact fidx mount sentinel and missing whole logical pages.");
        var doc = ProsperoNapsLayout.Parse(naps);
        var stds = doc.CblockInfos.Select((entry, index) => (Entry: entry, Index: index))
            .Where(item => !item.Entry.IsRunBase).ToArray();
        if (stds.Length != blocks.Count + 1)
            throw new InvalidDataException("Indexed NAPS map requires one STD per payload block and a terminator.");
        if (declaredEnd <= (doc.Counts.NumUBlocks - 1L) * PageSize || declaredEnd > (long)doc.Counts.NumUBlocks * PageSize)
            throw new InvalidDataException("Indexed NAPS fidx mount end disagrees with the header ublock count.");

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
                throw new InvalidDataException($"NAPS indexed logical offset disagrees with STD {stds[i].Index}.");
            starts[i] = logical;
            if (i == blocks.Count) break;
            Block block = blocks[i];
            int owner = block.SourceBlockIndex;
            if (block.IsAlias && owner >= 0)
            {
                if (owner >= i) throw new InvalidDataException("Indexed NAPS alias must reference an earlier payload block.");
                owner = sourceIndices[owner];
            }
            sourceIndices[i] = restored.Count;
            restored.Add(block with { UncompressedOffset = logical, SourceBlockIndex = owner });
        }
        if (starts[^1] != declaredEnd)
            throw new InvalidDataException("NAPS indexed logical coverage does not reach the exact fidx mount end.");

        // Check the entire acceleration table, not only the entries that introduced gaps.
        int firstStd = 0;
        for (int page = 0; page < pageIndices.Length; page++)
        {
            while (firstStd + 1 < starts.Length && starts[firstStd] < (long)page * PageSize) firstStd++;
            if (stds[firstStd].Index != pageIndices[page])
                throw new InvalidDataException($"NAPS u2c page {page} disagrees with the restored STD boundaries.");
        }
        var boundaries = starts.ToHashSet();
        ulong previousOffset = 0;
        foreach (var file in doc.FileOffsets)
        {
            if (file.UncompressedOffsetStart < previousOffset || file.UncompressedOffsetStart > (ulong)declaredEnd ||
                !boundaries.Contains((long)file.UncompressedOffsetStart))
                throw new InvalidDataException("NAPS fidx entry disagrees with the restored logical block boundaries.");
            previousOffset = file.UncompressedOffsetStart;
        }
        return restored;
    }
}
