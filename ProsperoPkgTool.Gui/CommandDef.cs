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

    /// <summary>
    /// Hidden from a simplified (Easy) view; rendered only in the advanced view. A hidden field
    /// still contributes <see cref="DefaultFor"/> so an Easy run sends the same defaults an
    /// advanced run would.
    /// </summary>
    public bool AdvancedOnly { get; init; }

    /// <summary>
    /// Default used in the simplified (Easy) view. Null falls back to <see cref="Default"/>, so a
    /// field can present a console-friendly value in Easy without changing the advanced default.
    /// </summary>
    public string? EasyDefault { get; init; }

    /// <summary>The default value for the active view: <see cref="EasyDefault"/> in Easy, else <see cref="Default"/>.</summary>
    public string DefaultFor(bool showAdvanced) =>
        showAdvanced ? Default : EasyDefault ?? Default;
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
