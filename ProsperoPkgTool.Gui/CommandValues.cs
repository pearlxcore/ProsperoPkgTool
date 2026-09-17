namespace ProsperoPkgTool.Gui;

/// <summary>
/// Fills a command's field values for a submitted run. Every field contributes a value: a rendered
/// control supplies the user's input, and a field hidden by the simplified (Easy) view supplies its
/// <see cref="CommandField.DefaultFor"/> instead. This keeps an Easy run equivalent to an advanced
/// run whose advanced-only knobs are left at their defaults, rather than dropping those keys (which
/// would silently flip default-on toggles off).
/// </summary>
public static class CommandValues
{
    public static Dictionary<string, string> Merge(
        CommandDef command, IReadOnlyDictionary<string, string> rendered, bool showAdvanced)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(rendered);

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (CommandField field in command.Fields)
        {
            values[field.Id] = rendered.TryGetValue(field.Id, out string? value)
                ? value
                : field.DefaultFor(showAdvanced);
        }
        return values;
    }
}
