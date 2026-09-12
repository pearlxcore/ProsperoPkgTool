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
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
            MaxDepth = 64,
        };
        using JsonDocument document = JsonDocument.Parse(stream, options);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("param.json root must be an object.");

        string? contentId = OptionalString(root, "contentId");
        if (string.IsNullOrWhiteSpace(contentId))
            throw new InvalidDataException("param.json is missing string property 'contentId'.");
        contentId = contentId.Trim().ToUpperInvariant();
        if (!ContentIdRegex().IsMatch(contentId))
            throw new InvalidDataException(
                $"param.json contentId '{contentId}' must use the 36-character Sony content ID form.");

        // The title id is derived from the content id whenever it is absent, malformed or stale. The
        // console keys the title off the content id, and real dumps occasionally carry an edited
        // content id with an old title id (or a different letter case).
        string? titleId = OptionalString(root, "titleId");
        titleId = string.IsNullOrWhiteSpace(titleId) ? contentId[7..16] : titleId.Trim().ToUpperInvariant();
        if (!TitleIdRegex().IsMatch(titleId))
            titleId = contentId[7..16];

        string? contentVersion = OptionalString(root, "contentVersion");
        // Real dumps carry publisher-specific category encodings (for example 0x01000000) that Sony's
        // tooling overwrites with 0. Only 1 selects additional content; every other value is treated
        // as a base application, matching the reference builder's CategoryTypeForMode.
        int category = OptionalInt(root, "applicationCategoryType") ?? 0;
        if (category != 1)
            category = 0;
        // The DRM token is descriptive metadata packaged verbatim; the CNT policy and the SI XML
        // handle any token, so it is not restricted here.
        string? applicationDrmType = OptionalString(root, "applicationDrmType");

        string? creationDate = null;
        if (root.TryGetProperty("pubtools", out JsonElement pubtools) && pubtools.ValueKind == JsonValueKind.Object)
            creationDate = OptionalString(pubtools, "creationDate");

        return new ProsperoParam(titleId, contentId, contentVersion, category, creationDate, applicationDrmType)
        {
            TitleName = OptionalString(root, "titleName"),
        };
    }

    private static string? OptionalString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String)
            return null;
        return value.GetString();
    }

    private static int? OptionalInt(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out int result))
            return null;
        return result;
    }

    [GeneratedRegex("^PPS[A-Z0-9][0-9]{5}$", RegexOptions.CultureInvariant)]
    private static partial Regex TitleIdRegex();

    [GeneratedRegex("^[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex ContentIdRegex();
}
