using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProsperoPkgTool.Gp5;

public sealed record ProsperoParam(
    string TitleId,
    string ContentId,
    string? ContentVersion,
    int ApplicationCategoryType,
    string? CreationDate)
{
    public string VolumeType => ApplicationCategoryType == 1
        ? Gp5Constants.AdditionalContentVolume
        : Gp5Constants.ApplicationVolume;
}

public static partial class ProsperoParamReader
{
    public static ProsperoParam Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        byte[] data = File.ReadAllBytes(path);
        var options = new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        };
        using JsonDocument document = JsonDocument.Parse(data, options);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("param.json root must be an object.");

        string titleId = RequiredString(root, "titleId");
        string contentId = RequiredString(root, "contentId");
        string? contentVersion = OptionalString(root, "contentVersion");
        int category = OptionalInt(root, "applicationCategoryType") ?? 0;
        string? creationDate = null;
        if (root.TryGetProperty("pubtools", out JsonElement pubtools))
        {
            if (pubtools.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("param.json pubtools must be an object.");
            creationDate = OptionalString(pubtools, "creationDate");
        }

        if (!TitleIdRegex().IsMatch(titleId))
            throw new InvalidDataException("param.json titleId must use the nine-character PPSA/PPSX form.");
        if (!ContentIdRegex().IsMatch(contentId))
            throw new InvalidDataException("param.json contentId must use the 36-character Sony content ID form.");
        if (!contentId.AsSpan(7, 9).Equals(titleId, StringComparison.Ordinal))
            throw new InvalidDataException("param.json contentId does not contain its titleId.");
        if (category is not 0 and not 1)
            throw new InvalidDataException("applicationCategoryType must be 0 (application) or 1 (additional content).");

        return new ProsperoParam(titleId, contentId, contentVersion, category, creationDate);
    }

    private static string RequiredString(JsonElement parent, string name) =>
        OptionalString(parent, name) is { Length: > 0 } value
            ? value
            : throw new InvalidDataException($"param.json is missing string property '{name}'.");

    private static string? OptionalString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value))
            return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"param.json property '{name}' must be a string.");
        return value.GetString();
    }

    private static int? OptionalInt(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value))
            return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int result))
            throw new InvalidDataException($"param.json property '{name}' must be an integer.");
        return result;
    }

    [GeneratedRegex("^PPS[A-Z0-9][0-9]{5}$", RegexOptions.CultureInvariant)]
    private static partial Regex TitleIdRegex();

    [GeneratedRegex("^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex ContentIdRegex();
}

