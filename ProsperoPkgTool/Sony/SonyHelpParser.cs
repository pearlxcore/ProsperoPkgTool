using System.Text.RegularExpressions;

namespace ProsperoPkgTool.Sony;

public sealed record SonyHelpCommand(string Name, IReadOnlySet<string> Options);

public static partial class SonyHelpParser
{
    public static IReadOnlySet<string> ParseAvailableCommands(string text)
    {
        var commands = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool inList = false;

        foreach (string sourceLine in Lines(text))
        {
            string line = sourceLine.Trim();
            if (line.Equals("Available command_name list:", StringComparison.OrdinalIgnoreCase))
            {
                inList = true;
                continue;
            }

            if (!inList)
                continue;
            if (line.StartsWith("For further information", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Usage", StringComparison.OrdinalIgnoreCase))
                break;
            if (line.Length == 0)
                continue;

            string name = line.Split('|', StringSplitOptions.TrimEntries)[0];
            if (CommandNameRegex().IsMatch(name))
                commands.Add(name);
        }

        return commands;
    }

    public static IReadOnlyDictionary<string, SonyHelpCommand> ParseDetailedHelp(string text)
    {
        var result = new Dictionary<string, SonyHelpCommand>(StringComparer.OrdinalIgnoreCase);
        string? currentName = null;
        HashSet<string>? currentOptions = null;

        foreach (string sourceLine in Lines(text))
        {
            string line = sourceLine.Trim();
            Match usage = UsageRegex().Match(line);
            if (usage.Success)
            {
                Commit();
                currentName = usage.Groups[1].Value;
                currentOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                continue;
            }

            if (currentOptions is not null && line.StartsWith("--", StringComparison.Ordinal))
            {
                string option = line.Split(' ', '\t', StringSplitOptions.RemoveEmptyEntries)[0];
                currentOptions.Add(option);
            }
        }

        Commit();
        return result;

        void Commit()
        {
            if (currentName is not null && currentOptions is not null)
                result[currentName] = new SonyHelpCommand(currentName, currentOptions);
        }
    }

    private static IEnumerable<string> Lines(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

    [GeneratedRegex("^[a-z][a-z0-9_-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex CommandNameRegex();

    [GeneratedRegex("^Usage of ([a-z][a-z0-9_-]*) command:$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex UsageRegex();
}

