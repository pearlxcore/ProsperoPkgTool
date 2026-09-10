using System.Globalization;

namespace ProsperoPkgTool.Gp5;

/// <summary>Clean-room conversion of supported GP5 chunk metadata into PlayGo build semantics.</summary>
public static class PlayGoProjectFactory
{
    /// <summary>
    /// Converts GP5 <c>chunk_info</c> and per-file <c>chunk</c> attributes. A chunk's optional
    /// <c>languages</c> attribute is accepted in this clean-room workflow only as an unsigned
    /// 64-bit mask (decimal or <c>0x</c>-prefixed hexadecimal); absent means all languages.
    /// </summary>
    public static PlayGoProject FromGp5(Gp5Project gp5, string contentId)
    {
        ArgumentNullException.ThrowIfNull(gp5);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentId);
        Gp5ChunkInfo info = gp5.Volume.ChunkInfo
            ?? throw new InvalidDataException("GP5 has no chunk_info; PlayGo package creation requires it.");
        if (info.ChunkCount != info.Chunks.Count || info.ScenarioCount != info.Scenarios.Count)
            throw new InvalidDataException("GP5 chunk_info counts do not match its chunk/scenario records.");

        var chunks = info.Chunks.OrderBy(c => c.Id).Select(c => new PlayGoChunk(c.Id, c.Label,
            ParseLanguageMask(c.Languages))).ToList();
        var scenarios = info.Scenarios.OrderBy(s => s.Id).Select(s => new PlayGoScenario(s.Id, s.Label,
            s.InitialChunkCount, ExpandSequence(s.Sequence, info.ChunkCount, s.Id))).ToList();
        var assignments = new Dictionary<string, byte>(StringComparer.Ordinal);
        foreach (Gp5FileEntry file in EnumerateFiles(gp5))
        {
            if (!file.Chunk.HasValue)
                continue;
            if (file.Chunk.Value is < 0 or > byte.MaxValue)
                throw new InvalidDataException($"GP5 file '{file.DestinationPath}' has an unsupported chunk ID {file.Chunk}.");
            string path = NormalizePath(file.DestinationPath);
            if (!assignments.TryAdd(path, (byte)file.Chunk.Value))
                throw new InvalidDataException($"GP5 assigns PlayGo chunk more than once to '{path}'.");
        }
        return new PlayGoProject
        {
            VersionMajor = 0x1000,
            ContentId = contentId,
            DefaultScenarioId = info.DefaultScenarioId,
            Chunks = chunks,
            Scenarios = scenarios,
            FileChunkAssignments = assignments,
        };
    }

    private static IReadOnlyList<int> ExpandSequence(string value, int count, int scenarioId)
    {
        if (!Gp5Validator.TryExpandSequence(value, count, out IReadOnlyList<int> chunks, out string? error))
            throw new InvalidDataException($"GP5 scenario {scenarioId}: {error}");
        return chunks;
    }

    private static IEnumerable<Gp5FileEntry> EnumerateFiles(Gp5Project project) => project.Layout == Gp5ContentLayout.FlatFiles
        ? project.Files
        : Flatten(project.RootDirectory).OfType<Gp5FileEntry>();

    private static IEnumerable<Gp5ContentEntry> Flatten(Gp5DirectoryEntry directory)
    {
        foreach (Gp5ContentEntry child in directory.Children)
        {
            yield return child;
            if (child is Gp5DirectoryEntry nested)
                foreach (Gp5ContentEntry descendant in Flatten(nested)) yield return descendant;
        }
    }

    private static string NormalizePath(string path)
    {
        try { return Gp5Path.NormalizeDestination(path).Replace('\\', '/').ToUpperInvariant(); }
        catch (ArgumentException exception) { throw new InvalidDataException(exception.Message, exception); }
    }

    private static ulong ParseLanguageMask(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return ulong.MaxValue;
        string text = value.Trim();
        NumberStyles style = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? NumberStyles.AllowHexSpecifier : NumberStyles.None;
        if (style != NumberStyles.None) text = text[2..];
        if (!ulong.TryParse(text, style, CultureInfo.InvariantCulture, out ulong mask))
            throw new InvalidDataException("GP5 chunk languages must be a decimal or 0x-prefixed uint64 mask in the clean-room PlayGo workflow.");
        return mask;
    }
}
