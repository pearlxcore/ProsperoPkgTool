using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProsperoPkgTool.Gp5;

public sealed record ProsperoParam(
    string TitleId,
    string ContentId,
    string? ContentVersion,
    int ApplicationCategoryType,
    string? CreationDate,
    string? ApplicationDrmType)
{
    /// <summary>Optional human-readable title (param.json <c>titleName</c>); empty when absent.</summary>
    public string? TitleName { get; init; }

    public string VolumeType => ApplicationCategoryType == 1
        ? Gp5Constants.AdditionalContentVolume
        : Gp5Constants.ApplicationVolume;
}

public static partial class ProsperoParamReader
{
    public static ProsperoParam Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Read(File.ReadAllBytes(path));
    }

    public static ProsperoParam Read(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var stream = new MemoryStream(data, writable: false);
        return Read(stream);
    }

    public static ProsperoParam Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var options = new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64,
        };
        using JsonDocument document = JsonDocument.Parse(stream, options);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("param.json root must be an object.");

        string titleId = RequiredString(root, "titleId");
        string contentId = RequiredString(root, "contentId");
        string? contentVersion = OptionalString(root, "contentVersion");
        int category = OptionalInt(root, "applicationCategoryType") ?? 0;
        string? applicationDrmType = OptionalString(root, "applicationDrmType");
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
        // Real dumps carry publisher-specific category encodings (for example 0x01000000) that Sony's
        // tooling overwrites with 0. Only 1 selects additional content; every other value is treated
        // as a base application, matching the reference builder's CategoryTypeForMode.
        if (category != 1)
            category = 0;
        if (applicationDrmType is not null &&
            applicationDrmType is not "standard" and not "free" and not "freemium")
            throw new InvalidDataException("applicationDrmType must be standard, free, or freemium.");

        return new ProsperoParam(titleId, contentId, contentVersion, category, creationDate, applicationDrmType)
        {
            TitleName = OptionalString(root, "titleName"),
        };
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
