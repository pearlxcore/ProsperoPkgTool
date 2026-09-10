namespace ProsperoPkgTool.Containers;

/// <summary>
/// Independent, field-by-field comparison of two PS5 containers for PC-side parity testing.
/// Produces the envelope/header/entry-table differences of the reference comparison and extends
/// them with FIH/segment geometry plus inner-PFS path lists when both packages decode.
/// </summary>
public static class ProsperoContainerComparer
{
    /// <summary>Inner-PFS comparison is skipped above this PFS size to bound memory use.</summary>
    private const long InnerPfsMemoryLimit = 1L << 29; // 512 MiB

    private static readonly string[] SegmentNames = ["LIH", "FIH", "PFS", "SC", "SI"];

    /// <summary>Returns an empty list when the containers match; otherwise one line per difference.</summary>
    public static IReadOnlyList<string> Compare(string referencePath, string candidatePath)
    {
        ProsperoPackageInspection reference = ProsperoPackageReader.Read(referencePath);
        ProsperoPackageInspection candidate = ProsperoPackageReader.Read(candidatePath);
        var differences = new List<string>();
        CompareStructure(reference, candidate, differences);
        CompareInnerPfs(reference, referencePath, candidate, candidatePath, differences);
        return differences;
    }

    private static void CompareStructure(
        ProsperoPackageInspection reference, ProsperoPackageInspection candidate, List<string> differences)
    {
        if (reference.Kind != candidate.Kind)
            differences.Add($"Type: {reference.Kind} != {candidate.Kind}");
        if (reference.Cnt.EntryCount != candidate.Cnt.EntryCount)
            differences.Add($"EntryCount: {reference.Cnt.EntryCount} != {candidate.Cnt.EntryCount}");
        if (reference.Cnt.EntryTableOffset != candidate.Cnt.EntryTableOffset)
            differences.Add($"EntryTableOffset: {reference.Cnt.EntryTableOffset:X} != {candidate.Cnt.EntryTableOffset:X}");
        if (!string.Equals(reference.Cnt.ContentId, candidate.Cnt.ContentId, StringComparison.Ordinal))
            differences.Add($"ContentId: {reference.Cnt.ContentId} != {candidate.Cnt.ContentId}");
        if (reference.Cnt.ContentType != candidate.Cnt.ContentType)
            differences.Add($"ContentType: {reference.Cnt.ContentType} != {candidate.Cnt.ContentType}");

        int shared = Math.Min(reference.Entries.Count, candidate.Entries.Count);
        for (int i = 0; i < shared; i++)
        {
            ProsperoCntEntry a = reference.Entries[i];
            ProsperoCntEntry b = candidate.Entries[i];
            if (a.Id != b.Id || a.DataSize != b.DataSize || a.Flags1 != b.Flags1)
                differences.Add(
                    $"Entry[{i}] {a.DisplayName}/{b.DisplayName}: id={a.Id:X}/{b.Id:X} " +
                    $"size={a.DataSize}/{b.DataSize} flags={a.Flags1:X}/{b.Flags1:X}");
        }
        if (reference.Entries.Count != candidate.Entries.Count)
            differences.Add($"Entry count differs: {reference.Entries.Count} vs {candidate.Entries.Count}");

        CompareFih(reference, candidate, differences);
        CompareSegments(reference, candidate, differences);
    }

    private static void CompareFih(
        ProsperoPackageInspection reference, ProsperoPackageInspection candidate, List<string> differences)
    {
        if (reference.Fih is not { } a || candidate.Fih is not { } b)
        {
            if ((reference.Fih is null) != (candidate.Fih is null))
                differences.Add($"FIH: {(reference.Fih is null ? "absent" : "present")} != {(candidate.Fih is null ? "absent" : "present")}");
            return;
        }

        if (a.FormatVersion != b.FormatVersion)
            differences.Add($"FIH.FormatVersion: {a.FormatVersion} != {b.FormatVersion}");
        if (a.SignedByte != b.SignedByte)
            differences.Add($"FIH.SignedByte: 0x{a.SignedByte:X2} != 0x{b.SignedByte:X2}");
        if (a.PfsOffset != b.PfsOffset)
            differences.Add($"FIH.PfsOffset: 0x{a.PfsOffset:X} != 0x{b.PfsOffset:X}");
        if (a.PfsSize != b.PfsSize)
            differences.Add($"FIH.PfsSize: 0x{a.PfsSize:X} != 0x{b.PfsSize:X}");
        if (a.CntOffset != b.CntOffset)
            differences.Add($"FIH.CntOffset: 0x{a.CntOffset:X} != 0x{b.CntOffset:X}");
    }

    private static void CompareSegments(
        ProsperoPackageInspection reference, ProsperoPackageInspection candidate, List<string> differences)
    {
        var referenceByName = reference.Segments.ToDictionary(s => s.Name, s => s, StringComparer.Ordinal);
        var candidateByName = candidate.Segments.ToDictionary(s => s.Name, s => s, StringComparer.Ordinal);
        foreach (string name in SegmentNames)
        {
            bool hasReference = referenceByName.TryGetValue(name, out ProsperoPackageSegment? a);
            bool hasCandidate = candidateByName.TryGetValue(name, out ProsperoPackageSegment? b);
            if (hasReference && !hasCandidate)
            {
                differences.Add($"Segment {name}: present in reference (0x{a!.Offset:X}, 0x{a.Size:X}) but absent in candidate");
                continue;
            }
            if (!hasReference && hasCandidate)
            {
                differences.Add($"Segment {name}: absent in reference but present in candidate (0x{b!.Offset:X}, 0x{b.Size:X})");
                continue;
            }
            if (!hasReference || !hasCandidate)
                continue;
            if (a!.Offset != b!.Offset)
                differences.Add($"Segment {name}.Offset: 0x{a.Offset:X} != 0x{b.Offset:X}");
            if (a.Size != b.Size)
                differences.Add($"Segment {name}.Size: 0x{a.Size:X} != 0x{b.Size:X}");
        }
    }

    private static void CompareInnerPfs(
        ProsperoPackageInspection reference, string referencePath,
        ProsperoPackageInspection candidate, string candidatePath,
        List<string> differences)
    {
        if (!TryReadInnerPfs(reference, referencePath, out IReadOnlyList<ProsperoInnerPfsReader.Entry>? referenceEntries) ||
            !TryReadInnerPfs(candidate, candidatePath, out IReadOnlyList<ProsperoInnerPfsReader.Entry>? candidateEntries))
            return;

        var referenceMap = referenceEntries.ToDictionary(e => e.Path, e => (e.IsDirectory, e.Size), StringComparer.Ordinal);
        var candidateMap = candidateEntries.ToDictionary(e => e.Path, e => (e.IsDirectory, e.Size), StringComparer.Ordinal);
        foreach (string path in referenceMap.Keys.Union(candidateMap.Keys, StringComparer.Ordinal).OrderBy(p => p, StringComparer.Ordinal))
        {
            bool inReference = referenceMap.TryGetValue(path, out (bool IsDirectory, long Size) r);
            bool inCandidate = candidateMap.TryGetValue(path, out (bool IsDirectory, long Size) c);
            if (inReference && !inCandidate)
            {
                differences.Add($"InnerPfs missing in candidate: {path}{SizeSuffix(r)}");
            }
            else if (!inReference && inCandidate)
            {
                differences.Add($"InnerPfs extra in candidate: {path}{SizeSuffix(c)}");
            }
            else if (r.IsDirectory != c.IsDirectory)
            {
                differences.Add($"InnerPfs type {path}: {(r.IsDirectory ? "dir" : "file")} != {(c.IsDirectory ? "dir" : "file")}");
            }
            else if (r.Size != c.Size)
            {
                differences.Add($"InnerPfs size {path}: {r.Size} != {c.Size}");
            }
        }
    }

    private static string SizeSuffix((bool IsDirectory, long Size) entry) =>
        entry.IsDirectory ? string.Empty : $" ({entry.Size})";

    private static bool TryReadInnerPfs(
        ProsperoPackageInspection inspection, string path, out IReadOnlyList<ProsperoInnerPfsReader.Entry> entries)
    {
        entries = [];
        if (inspection.Kind != ProsperoPackageKind.FinalizedDebug)
            return false;
        if (inspection.Fih is not { } fih || fih.PfsSize > InnerPfsMemoryLimit)
            return false;
        try
        {
            ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(path);
            entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
            return true;
        }
        catch (Exception)
        {
            // Inner-PFS comparison is best-effort: foreign/keyed layouts that our reader cannot
            // decode are simply skipped rather than failing the whole comparison.
            return false;
        }
    }
}
