namespace ProsperoPkgTool.Sony;

public enum SonyCommandRisk
{
    ReadOnly,
    WritesOutput,
    MutatesInput,
    ChangesConfiguration,
    WritesOpticalMedia,
}

public sealed record SonyCommandOption(string Name, bool TakesValue, string? ValueHint = null);

public sealed record SonyCommandDefinition(
    string Name,
    string Group,
    string Description,
    SonyCommandRisk Risk,
    IReadOnlyList<SonyCommandOption> Options);

