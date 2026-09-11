namespace ProsperoPkgTool.Gui;

public enum FieldKind
{
    File,
    SaveFile,
    Folder,
    Text,
    MultiText,
    Combo,
    Check,
    Numeric,
    Slider,
}

public sealed class CommandField
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public required FieldKind Kind { get; init; }
    public string Filter { get; init; } = string.Empty;
    public string[] Choices { get; init; } = [];
    public string[]? ChoiceRemarks { get; init; }
    public string Default { get; init; } = string.Empty;
    public string Hint { get; init; } = string.Empty;
    public int Minimum { get; init; }
    public int Maximum { get; init; }
    public int Increment { get; init; } = 1;
}

public sealed class CommandDef
{
    public required string Name { get; init; }
    public required string Group { get; init; }
    public required string Title { get; init; }
    public string Description { get; init; } = string.Empty;
    public required string CliWord { get; init; }
    public required CommandField[] Fields { get; init; }
    public required Func<IReadOnlyDictionary<string, string>, string[]> BuildArgs { get; init; }
    public bool UsesSelectedPackage { get; init; }
    public bool RequiresSonyTool { get; init; }
    public string Confirmation { get; init; } = string.Empty;

    public const string DefaultPasscode = "00000000000000000000000000000000";
}
