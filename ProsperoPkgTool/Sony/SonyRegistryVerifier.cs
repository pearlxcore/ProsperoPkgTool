namespace ProsperoPkgTool.Sony;

public sealed record SonyRegistryMismatch(
    IReadOnlyList<string> MissingCommands,
    IReadOnlyList<string> UnknownCommands,
    IReadOnlyDictionary<string, IReadOnlyList<string>> MissingOptions,
    IReadOnlyDictionary<string, IReadOnlyList<string>> UnknownOptions)
{
    public bool IsComplete => MissingCommands.Count == 0 && UnknownCommands.Count == 0 &&
                              MissingOptions.Count == 0 && UnknownOptions.Count == 0;
}

public static class SonyRegistryVerifier
{
    public static SonyRegistryMismatch Compare(string commandListHelp, string detailedHelp)
    {
        IReadOnlySet<string> discovered = SonyHelpParser.ParseAvailableCommands(commandListHelp);
        IReadOnlyDictionary<string, SonyHelpCommand> details = SonyHelpParser.ParseDetailedHelp(detailedHelp);
        var registeredNames = SonyCommandRegistry.ByName.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);

        string[] missingCommands = discovered.Except(registeredNames, StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).ToArray();
        string[] unknownCommands = registeredNames.Except(discovered, StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase).ToArray();

        var missingOptions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        var unknownOptions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        foreach ((string name, SonyHelpCommand help) in details)
        {
            if (!SonyCommandRegistry.TryGet(name, out SonyCommandDefinition? definition))
                continue;

            var registeredOptions = definition.Options.Select(option => option.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            string[] missing = help.Options.Except(registeredOptions, StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] unknown = registeredOptions.Except(help.Options, StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase).ToArray();
            if (missing.Length > 0)
                missingOptions[name] = missing;
            if (unknown.Length > 0)
                unknownOptions[name] = unknown;
        }

        return new SonyRegistryMismatch(missingCommands, unknownCommands, missingOptions, unknownOptions);
    }
}

