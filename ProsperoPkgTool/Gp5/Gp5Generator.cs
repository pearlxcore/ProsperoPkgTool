namespace ProsperoPkgTool.Gp5;

public sealed class Gp5GeneratorOptions
{
    public string Passcode { get; init; } = Gp5Constants.DefaultPasscode;
}

public sealed record Gp5GenerationResult(
    Gp5Project Project,
    SourceFolderInspection Source,
    ValidationReport Validation);

public static class Gp5Generator
{
    public static Gp5GenerationResult Generate(
        string sourceDirectory,
        Gp5GeneratorOptions? options = null,
        string? intendedProjectPath = null)
    {
        options ??= new Gp5GeneratorOptions();
        SourceFolderInspection source = SourceFolderValidator.Inspect(sourceDirectory);
        if (source.Param is null)
            throw new InvalidDataException("A valid sce_sys/param.json is required before GP5 generation.");

        ProsperoParam param = source.Param;
        var project = new Gp5Project
        {
            Format = "gp5",
            Version = "1000",
            Layout = Gp5ContentLayout.FlatFiles,
            Volume = new Gp5Volume
            {
                VolumeType = param.VolumeType,
                Package = new Gp5Package
                {
                    ContentId = param.ContentId,
                    Passcode = options.Passcode,
                    CreationDate = param.CreationDate,
                },
            },
        };

        if (param.ApplicationCategoryType == 0)
            project.Volume.ChunkInfo = BuildChunkInfo(source.PlayGo);

        foreach (string relative in source.IncludedFiles)
        {
            project.Files.Add(new Gp5FileEntry
            {
                DestinationPath = Gp5Path.ToProjectRelative(relative),
                SourcePath = Gp5Path.ToProjectRelative(relative),
            });
        }

        string projectPath = intendedProjectPath ?? Path.Combine(source.RootPath, param.TitleId + ".gp5");
        ValidationReport projectValidation = Gp5Validator.Validate(project, projectPath);
        var combined = new ValidationReport();
        combined.AddRange(source.Validation.Issues);
        combined.AddRange(projectValidation.Issues);
        return new Gp5GenerationResult(project, source, combined);
    }

    private static Gp5ChunkInfo BuildChunkInfo(PlayGoProject? playGo)
    {
        if (playGo is null)
        {
            var defaults = new Gp5ChunkInfo
            {
                ChunkCount = 1,
                ScenarioCount = 1,
                DefaultScenarioId = 0,
            };
            defaults.Chunks.Add(new Gp5Chunk { Id = 0, Label = "Chunk #0" });
            defaults.Scenarios.Add(new Gp5Scenario
            {
                Id = 0,
                InitialChunkCount = 1,
                Label = "Scenario #0",
                Type = "playmode",
                Sequence = "0",
            });
            return defaults;
        }

        var info = new Gp5ChunkInfo
        {
            ChunkCount = playGo.Chunks.Count,
            ScenarioCount = playGo.Scenarios.Count,
            DefaultScenarioId = playGo.DefaultScenarioId,
        };
        foreach (PlayGoChunk chunk in playGo.Chunks)
        {
            info.Chunks.Add(new Gp5Chunk
            {
                Id = chunk.Id,
                Label = chunk.Label,
                // The GP5 <chunk> `languages` attribute is a space-separated language-tag list; the
                // known-good publisher project omits it, so the binary language mask is not emitted.
            });
        }
        foreach (PlayGoScenario scenario in playGo.Scenarios)
        {
            info.Scenarios.Add(new Gp5Scenario
            {
                Id = scenario.Id,
                InitialChunkCount = scenario.InitialChunkCount,
                Label = scenario.Label,
                Type = "playmode",
                Sequence = FormatSequence(scenario.Chunks),
            });
        }
        return info;
    }

    internal static string FormatSequence(IReadOnlyList<int> chunks)
    {
        var parts = new List<string>();
        for (int index = 0; index < chunks.Count;)
        {
            int start = chunks[index];
            int end = start;
            int next = index + 1;
            while (next < chunks.Count && chunks[next] == end + 1)
            {
                end = chunks[next];
                next++;
            }
            parts.Add(end > start ? $"{start}-{end}" : start.ToString(System.Globalization.CultureInfo.InvariantCulture));
            index = next;
        }
        return string.Join(' ', parts);
    }
}
