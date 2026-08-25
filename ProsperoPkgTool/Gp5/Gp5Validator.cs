using System.Globalization;
using System.Text.RegularExpressions;

namespace ProsperoPkgTool.Gp5;

public static partial class Gp5Validator
{
    public static ValidationReport Validate(Gp5Project project, string? projectPath = null)
    {
        ArgumentNullException.ThrowIfNull(project);
        var report = new ValidationReport();

        if (!project.Format.Equals("gp5", StringComparison.Ordinal))
            report.Error("GP5_FORMAT", "Project fmt must be 'gp5'.");
        if (project.Version is not null && project.Version != "1000")
            report.Warning("GP5_VERSION", $"Unrecognized GP5 project version '{project.Version}'.");

        ValidateVolume(project.Volume, report);
        ValidateContents(project, projectPath, report);
        return report;
    }

    private static void ValidateVolume(Gp5Volume volume, ValidationReport report)
    {
        if (volume.VolumeType is not Gp5Constants.ApplicationVolume and not Gp5Constants.AdditionalContentVolume)
            report.Error("VOLUME_TYPE", "Volume type must be prospero_app or prospero_ac.");

        Gp5Package package = volume.Package;
        if (package.Passcode.Length != 32 || package.Passcode.Any(character => character is < ' ' or > '~'))
            report.Error("PASSCODE", "Package passcode must contain exactly 32 printable ASCII characters.");
        if (!string.IsNullOrWhiteSpace(package.ContentId) && !ContentIdRegex().IsMatch(package.ContentId))
            report.Error("CONTENT_ID", "Package content_id must use the 36-character Sony content ID format.");
        if (!string.IsNullOrWhiteSpace(package.EntitlementKey) && !Hex32Regex().IsMatch(package.EntitlementKey))
            report.Error("ENTITLEMENT_KEY", "entitlement_key must contain exactly 32 hexadecimal characters.");
        if (!string.IsNullOrWhiteSpace(package.CreationDate) && !ValidDate(package.CreationDate))
            report.Error("CREATION_DATE", "c_date must be YYYY-MM-DD or YYYY-MM-DD HH:mm:ss.");

        if (volume.VolumeType == Gp5Constants.ApplicationVolume)
        {
            if (volume.ChunkInfo is null)
                report.Error("CHUNK_INFO", "Application projects require chunk_info.");
            else
                ValidateChunkInfo(volume.ChunkInfo, report);
        }
        else if (volume.ChunkInfo is not null)
        {
            report.Warning("AC_CHUNK_INFO", "Additional-content projects normally omit chunk_info.");
            ValidateChunkInfo(volume.ChunkInfo, report);
        }
    }

    private static void ValidateChunkInfo(Gp5ChunkInfo info, ValidationReport report)
    {
        if (info.ChunkCount != info.Chunks.Count)
            report.Error("CHUNK_COUNT", $"chunk_count is {info.ChunkCount}, but {info.Chunks.Count} chunks are defined.");
        if (info.ScenarioCount != info.Scenarios.Count)
            report.Error("SCENARIO_COUNT", $"scenario_count is {info.ScenarioCount}, but {info.Scenarios.Count} scenarios are defined.");
        if (info.ChunkCount is < 1 or > 1000)
            report.Error("CHUNK_RANGE", "Application chunk count must be between 1 and 1000.");
        if (info.ScenarioCount is < 1 or > 32)
            report.Error("SCENARIO_RANGE", "Application scenario count must be between 1 and 32.");

        int[] chunkIds = info.Chunks.Select(chunk => chunk.Id).ToArray();
        if (chunkIds.Distinct().Count() != chunkIds.Length)
            report.Error("CHUNK_ID_DUPLICATE", "Chunk IDs must be unique.");
        if (info.ChunkCount is >= 0 and <= 1000 &&
            !IsContiguousFromZero(chunkIds, info.ChunkCount))
            report.Error("CHUNK_ID_SEQUENCE", "Chunk IDs must be contiguous from zero.");

        int[] scenarioIds = info.Scenarios.Select(scenario => scenario.Id).ToArray();
        if (scenarioIds.Distinct().Count() != scenarioIds.Length)
            report.Error("SCENARIO_ID_DUPLICATE", "Scenario IDs must be unique.");
        if (info.ScenarioCount is >= 0 and <= 32 &&
            !IsContiguousFromZero(scenarioIds, info.ScenarioCount))
            report.Error("SCENARIO_ID_SEQUENCE", "Scenario IDs must be contiguous from zero.");
        if (!scenarioIds.Contains(info.DefaultScenarioId))
            report.Error("DEFAULT_SCENARIO", "default_id does not identify a defined scenario.");

        if (!string.IsNullOrWhiteSpace(info.DefaultLanguage) &&
            (string.IsNullOrWhiteSpace(info.SupportedLanguages) ||
             !SplitWords(info.SupportedLanguages).Contains(info.DefaultLanguage, StringComparer.Ordinal)))
            report.Error("DEFAULT_LANGUAGE", "default_language must be present in supported_languages.");

        foreach (Gp5Scenario scenario in info.Scenarios)
        {
            if (!scenario.Type.Equals("playmode", StringComparison.Ordinal))
                report.Error("SCENARIO_TYPE", $"Scenario {scenario.Id} type must be playmode.");
            if (info.ChunkCount is < 1 or > 1000)
                continue;
            if (!TryExpandSequence(scenario.Sequence, info.ChunkCount, out IReadOnlyList<int> chunks, out string? error))
            {
                report.Error("SCENARIO_SEQUENCE", $"Scenario {scenario.Id}: {error}");
                continue;
            }
            if (scenario.InitialChunkCount < 0 || scenario.InitialChunkCount > chunks.Count)
                report.Error("INITIAL_CHUNKS", $"Scenario {scenario.Id} initial_chunk_count exceeds its sequence length.");
        }
    }

    private static void ValidateContents(Gp5Project project, string? projectPath, ValidationReport report)
    {
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (project.Layout == Gp5ContentLayout.FlatFiles)
        {
            if (project.Files.Count == 0)
                report.Warning("EMPTY_PROJECT", "The GP5 project contains no files.");
            foreach (Gp5FileEntry file in project.Files)
                ValidateEntry(file, false, project, projectPath, destinations, report);
            return;
        }

        ValidateEntry(project.RootDirectory, true, project, projectPath, destinations, report);
        foreach (Gp5ContentEntry child in Flatten(project.RootDirectory))
            ValidateEntry(child, false, project, projectPath, destinations, report);
    }

    private static void ValidateEntry(
        Gp5ContentEntry entry,
        bool isRoot,
        Gp5Project project,
        string? projectPath,
        ISet<string> destinations,
        ValidationReport report)
    {
        if (!isRoot)
        {
            try
            {
                string destination = Gp5Path.NormalizeDestination(entry.DestinationPath);
                if (!destinations.Add(destination))
                    report.Error("DUPLICATE_DESTINATION", $"Duplicate destination path '{destination}'.", destination);
            }
            catch (ArgumentException exception)
            {
                report.Error("DESTINATION_PATH", exception.Message, entry.DestinationPath);
            }
        }

        if (entry.Chunk.HasValue &&
            (project.Volume.ChunkInfo is null || entry.Chunk < 0 || entry.Chunk >= project.Volume.ChunkInfo.ChunkCount))
            report.Error("ENTRY_CHUNK", $"Entry chunk {entry.Chunk} is not defined.", entry.DestinationPath);

        bool needsSource = entry is Gp5FileEntry || entry is Gp5DirectoryEntry { Virtual: false };
        if (needsSource && string.IsNullOrWhiteSpace(entry.SourcePath))
        {
            report.Error("SOURCE_PATH", "A non-virtual entry requires src_path.", entry.DestinationPath);
            return;
        }
        if (projectPath is null || string.IsNullOrWhiteSpace(entry.SourcePath))
            return;

        try
        {
            string resolved = Gp5Path.ResolveSource(projectPath, entry.SourcePath);
            string projectDirectory = Path.GetDirectoryName(Path.GetFullPath(projectPath))!;
            if (!Gp5Path.IsWithin(projectDirectory, resolved))
                report.Warning("EXTERNAL_SOURCE", "Source path is outside the GP5 project directory.", entry.SourcePath);
            bool exists = entry is Gp5FileEntry ? File.Exists(resolved) : Directory.Exists(resolved);
            if (!exists)
                report.Error("SOURCE_MISSING", "Source path does not exist.", entry.SourcePath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            report.Error("SOURCE_PATH", exception.Message, entry.SourcePath);
        }
    }

    public static bool TryExpandSequence(
        string sequence,
        int chunkCount,
        out IReadOnlyList<int> chunks,
        out string? error)
    {
        var result = new List<int>();
        var seen = new HashSet<int>();
        foreach (string token in SplitWords(sequence))
        {
            string[] range = token.Split('-', StringSplitOptions.None);
            if (range.Length is < 1 or > 2 || !int.TryParse(range[0], out int start) ||
                (range.Length == 2 && !int.TryParse(range[1], out _)))
            {
                chunks = [];
                error = $"Invalid chunk token '{token}'.";
                return false;
            }
            int end = range.Length == 2 ? int.Parse(range[1], CultureInfo.InvariantCulture) : start;
            if (start < 0 || end < start || end >= chunkCount)
            {
                chunks = [];
                error = $"Chunk token '{token}' is outside 0..{chunkCount - 1}.";
                return false;
            }
            for (int chunk = start; chunk <= end; chunk++)
            {
                if (!seen.Add(chunk))
                {
                    chunks = [];
                    error = $"Chunk {chunk} appears more than once.";
                    return false;
                }
                result.Add(chunk);
            }
        }
        chunks = result;
        error = result.Count == 0 ? "Scenario sequence is empty." : null;
        return result.Count > 0;
    }

    private static IEnumerable<Gp5ContentEntry> Flatten(Gp5DirectoryEntry directory)
    {
        foreach (Gp5ContentEntry child in directory.Children)
        {
            yield return child;
            if (child is Gp5DirectoryEntry nested)
            {
                foreach (Gp5ContentEntry descendant in Flatten(nested))
                    yield return descendant;
            }
        }
    }

    private static string[] SplitWords(string value) =>
        value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool IsContiguousFromZero(IEnumerable<int> values, int expectedCount)
    {
        int expected = 0;
        foreach (int value in values.Order())
        {
            if (value != expected++)
                return false;
        }
        return expected == expectedCount;
    }

    private static bool ValidDate(string value) =>
        DateTime.TryParseExact(value, ["yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss"],
            CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    [GeneratedRegex("^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex ContentIdRegex();

    [GeneratedRegex("^[0-9A-Fa-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex Hex32Regex();
}
