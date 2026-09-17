using System.Collections;
using Block = ProsperoPkgTool.Containers.ProsperoPs5InnerImageReader.InnerBlock;

namespace ProsperoPkgTool.Containers;

/// <summary>A normalized map and the evidence used to select its interpretation.</summary>
public sealed class NapsBlockPlan : IReadOnlyList<Block>
{
    private readonly IReadOnlyList<Block> _blocks;
    internal NapsBlockPlan(string dialect, IReadOnlyList<Block> blocks, IReadOnlyList<string> diagnostics)
        => (Dialect, _blocks, Diagnostics) = (dialect, blocks, diagnostics);
    public string Dialect { get; }
    public IReadOnlyList<string> Diagnostics { get; }
    public int Count => _blocks.Count;
    public Block this[int index] => _blocks[index];
    public IEnumerator<Block> GetEnumerator() => _blocks.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

internal interface INapsDialect
{
    string Id { get; }
    IReadOnlyList<Block> Decode(ReadOnlySpan<byte> naps, long sourceLength);
}

internal static class NapsDialectRegistry
{
    private sealed class CoffsetDialect(bool nativeSpans) : INapsDialect
    {
        public string Id => nativeSpans ? "native-span-v1" : "compatible-coffset-v1";
        public IReadOnlyList<Block> Decode(ReadOnlySpan<byte> naps, long sourceLength) =>
            ProsperoPs5InnerImageReader.WalkBlocksCore(naps, sourceLength, nativeSpans);
    }

    private sealed class IndexedCoffsetDialect : INapsDialect
    {
        public string Id => "indexed-coffset-v1";
        public IReadOnlyList<Block> Decode(ReadOnlySpan<byte> naps, long sourceLength) =>
            NapsIndexedLogicalMap.Restore(naps,
                ProsperoPs5InnerImageReader.WalkBlocksCore(naps, sourceLength, nativeSpans: false));
    }

    private static readonly INapsDialect[] Dialects =
        [new CoffsetDialect(false), new CoffsetDialect(true), new IndexedCoffsetDialect()];

    internal static NapsBlockPlan Select(ReadOnlySpan<byte> naps, long sourceLength,
        Action<IReadOnlyList<Block>>? probe)
    {
        var diagnostics = new List<string>();
        var candidates = new List<(string Id, IReadOnlyList<Block> Blocks)>();
        long? declaredEnd = NapsIndexedLogicalMap.ReadMountEnd(naps);
        foreach (var dialect in Dialects)
        {
            try
            {
                var blocks = dialect.Decode(naps, sourceLength);
                long end = blocks[^1].UncompressedOffset + blocks[^1].UncompressedLength;
                if (declaredEnd is { } expected && end != expected)
                    throw new InvalidDataException($"Logical coverage {end} disagrees with the exact NAPS fidx mount end {expected}.");
                candidates.Add((dialect.Id, blocks));
            }
            catch (InvalidDataException ex) { diagnostics.Add($"{dialect.Id}: {ex.Message}"); }
        }
        if (candidates.Skip(1).Any(candidate => !Equivalent(candidates[0].Blocks, candidate.Blocks)))
        {
            if (probe is null)
                throw new InvalidDataException("Ambiguous NAPS interpretations require a PFS metadata probe.");
            for (int i = candidates.Count - 1; i >= 0; i--)
            {
                try { probe(candidates[i].Blocks); }
                catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException or OverflowException)
                {
                    diagnostics.Add($"{candidates[i].Id}: PFS probe: {ex.Message}");
                    candidates.RemoveAt(i);
                }
            }
            if (candidates.Skip(1).Any(candidate => !Equivalent(candidates[0].Blocks, candidate.Blocks)))
                throw new InvalidDataException("Ambiguous NAPS interpretations: incompatible maps both passed PFS metadata validation.");
        }
        if (candidates.Count == 0)
            throw new InvalidDataException("No supported NAPS interpretation. " + string.Join(" | ", diagnostics));
        foreach (var equivalent in candidates.Skip(1))
            diagnostics.Add($"{equivalent.Id}: equivalent logical map.");
        return new NapsBlockPlan(candidates[0].Id, candidates[0].Blocks, diagnostics);
    }

    // Compare what a read returns, ignoring RUN bookkeeping and encoded bytes of zero spans.
    private static bool Equivalent(IReadOnlyList<Block> left, IReadOnlyList<Block> right)
    {
        if (left.Count != right.Count) return false;
        for (int i = 0; i < left.Count; i++)
        {
            Block a = Normalize(left, i), b = Normalize(right, i);
            if (a != b) return false;
        }
        return true;
    }

    private static Block Normalize(IReadOnlyList<Block> blocks, int index)
    {
        Block b = blocks[index];
        if (b.IsAlias && (b.SourceBlockIndex < 0 || b.SourceBlockIndex >= index ||
            blocks[b.SourceBlockIndex].UncompressedLength < b.UncompressedLength))
            b = b with { IsZeroHole = true };
        if (b.IsZeroHole)
            return new Block(0, 0, 0, b.UncompressedOffset, b.UncompressedLength, false, true);
        return b with { RunIndex = -1, EvenCompressedLength = b.IsKraken ? b.EvenCompressedLength : 0,
            CompressedLength = !b.IsKraken && !b.IsAlias ? b.UncompressedLength : b.CompressedLength };
    }

    internal static void ProbePfs(IReadOnlyList<Block> blocks, long sourceLength,
        Func<long, int, byte[]> read, long superblockHint = -1)
    {
        // Bound detection work even when a bad interpretation sends the PFS scanner through
        // payload blocks. This is a probe budget, not a limit on normal package enumeration.
        long remaining = 32L * 1024 * 1024;
        byte[] ReadProbe(long offset, int length)
        {
            if (length > remaining)
                throw new NotSupportedException("NAPS interpretation remains ambiguous: metadata probe exceeded its 32 MiB source-read budget.");
            remaining -= length;
            return read(offset, length);
        }
        using var mount = new ProsperoInnerMountStream(blocks, sourceLength, ReadProbe);
        var entries = ProsperoInnerPfsReader.Enumerate(mount, superblockHint);
        if (!entries.Any(e => e.IsDirectory && e.Path == "/uroot"))
            throw new InvalidDataException("NAPS metadata probe found no /uroot directory.");
    }
}
