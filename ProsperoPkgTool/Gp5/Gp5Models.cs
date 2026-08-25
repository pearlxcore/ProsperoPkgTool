namespace ProsperoPkgTool.Gp5;

public enum Gp5ContentLayout
{
    FlatFiles,
    RootDirectory,
}

public sealed class Gp5Project
{
    public string Format { get; set; } = "gp5";
    public string? Version { get; set; } = "1000";
    public Gp5Volume Volume { get; set; } = new();
    public Gp5ContentLayout Layout { get; set; } = Gp5ContentLayout.FlatFiles;
    public List<Gp5FileEntry> Files { get; } = [];
    public Gp5DirectoryEntry RootDirectory { get; set; } = new() { IsRoot = true, Virtual = true };
    public Dictionary<string, string> ExtraAttributes { get; } = new(StringComparer.Ordinal);
}

public sealed class Gp5Volume
{
    public string VolumeType { get; set; } = "prospero_app";
    public Gp5Package Package { get; set; } = new();
    public Gp5ChunkInfo? ChunkInfo { get; set; }
}

public sealed class Gp5Package
{
    public string? ContentId { get; set; }
    public string Passcode { get; set; } = Gp5Constants.DefaultPasscode;
    public string? CreationDate { get; set; }
    public string? EntitlementKey { get; set; }
    public string? StorageType { get; set; }
    public string? AppType { get; set; }
    public Dictionary<string, string> ExtraAttributes { get; } = new(StringComparer.Ordinal);
}

public sealed class Gp5ChunkInfo
{
    public int ChunkCount { get; set; }
    public int ScenarioCount { get; set; }
    public string? SupportedLanguages { get; set; }
    public string? DefaultLanguage { get; set; }
    public int DefaultScenarioId { get; set; }
    public List<Gp5Chunk> Chunks { get; } = [];
    public List<Gp5Scenario> Scenarios { get; } = [];
}

public sealed class Gp5Chunk
{
    public int Id { get; set; }
    public string Label { get; set; } = string.Empty;
    public string? Languages { get; set; }
    public Dictionary<string, string> ExtraAttributes { get; } = new(StringComparer.Ordinal);
}

public sealed class Gp5Scenario
{
    public int Id { get; set; }
    public string Type { get; set; } = "playmode";
    public int InitialChunkCount { get; set; }
    public string Label { get; set; } = string.Empty;
    public string Sequence { get; set; } = "0";
    public Dictionary<string, string> ExtraAttributes { get; } = new(StringComparer.Ordinal);
}

public abstract class Gp5ContentEntry
{
    public string DestinationPath { get; set; } = string.Empty;
    public string? SourcePath { get; set; }
    public int? Chunk { get; set; }
    public string? ContentConfigLabel { get; set; }
    public string? PfsCompression { get; set; }
    public Dictionary<string, string> ExtraAttributes { get; } = new(StringComparer.Ordinal);
}

public sealed class Gp5FileEntry : Gp5ContentEntry;

public sealed class Gp5DirectoryEntry : Gp5ContentEntry
{
    public bool IsRoot { get; set; }
    public bool? Virtual { get; set; }
    public string? DirectoryExclude { get; set; }
    public string? FileExclude { get; set; }
    public List<Gp5ContentEntry> Children { get; } = [];
}

public static class Gp5Constants
{
    public const string DefaultPasscode = "00000000000000000000000000000000";
    public const string ApplicationVolume = "prospero_app";
    public const string AdditionalContentVolume = "prospero_ac";
}

