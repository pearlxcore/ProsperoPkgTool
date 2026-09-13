using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using ProsperoPkgTool.Content;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Produces the canonical publisher <c>sce_sys/param.json</c> payload written into the CNT.
/// The source document is normalised (sorted keys, CRLF, no BOM) and completed with the
/// default application fields the console expects; the build timestamp replaces the
/// source <c>pubtools.creationDate</c>. This mirrors the observed publisher behaviour
/// without reproducing its implementation.
/// </summary>
public static class ProsperoPublisherParamJson
{
    /// <summary>Scene publisher tool version stamped into <c>pubtools.toolVersion</c>.</summary>
    public const string ToolVersion = "2.79";

    /// <summary>Default SDK version used when an ELF eboot lacks a readable <c>.sceversion</c>.</summary>
    private const ulong DefaultElfSdkVersion = 311029849265274880UL;

    /// <summary>Upper bound applied to a source <c>requiredSystemSoftwareVersion</c> (0x0900...).</summary>
    private const ulong RequiredSystemSoftwareVersionCap = 0x0900000000000000UL;

    private static readonly string[] SharingServiceIds = Enumerable.Range(0, 7).Select(_ => new string(' ', 19)).ToArray();

    /// <summary>Canonicalises <paramref name="sourceParamJson"/> for a base application package.</summary>
    /// <param name="sourceParamJson">Raw source <c>sce_sys/param.json</c> bytes.</param>
    /// <param name="timestamp">Build timestamp written as <c>pubtools.creationDate</c> (UTC).</param>
    /// <param name="sdkVersion">SDK version resolved from the source eboot; zero when unavailable.</param>
    public static byte[] Build(ReadOnlySpan<byte> sourceParamJson, DateTime timestamp, ulong sdkVersion)
    {
        JsonNode node;
        try
        {
            node = JsonNode.Parse(sourceParamJson) ?? throw new InvalidDataException("sce_sys/param.json is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("sce_sys/param.json is not valid JSON.", ex);
        }
        if (node is not JsonObject root)
            throw new InvalidDataException("sce_sys/param.json must contain a JSON object.");

        string versionFileUri = root["versionFileUri"]?.GetValue<string>() ?? string.Empty;
        if (versionFileUri.Length > 255)
            throw new InvalidDataException($"param.json versionFileUri is {versionFileUri.Length} characters; the publisher field is limited to 255.");
        root["versionFileUri"] = versionFileUri.PadRight(255, ' ');

        JsonNode? loudness = (root["pubtools"] as JsonObject)?["loudnessSnd0"]?.DeepClone();
        var pubtools = new JsonObject
        {
            ["creationDate"] = timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            ["toolVersion"] = ToolVersion,
        };
        if (loudness is not null)
            pubtools["loudnessSnd0"] = loudness;
        root["pubtools"] = pubtools;

        root["sdkVersion"] = VersionText(sdkVersion);
        ulong required = Math.Max(Math.Min(HexVersion(root["requiredSystemSoftwareVersion"]), RequiredSystemSoftwareVersionCap), sdkVersion);
        root["requiredSystemSoftwareVersion"] = VersionText(required);
        root["applicationCategoryType"] = 0;
        root["applicationDrmType"] ??= "standard";
        root["attribute"] ??= 0;
        root["attribute2"] ??= 0;
        root["attribute3"] ??= 0;
        root["conceptId"] ??= "10000000";
        root["masterVersion"] ??= "01.00";
        root["contentVersion"] ??= "01.000.000";
        root["ageLevel"] ??= new JsonObject { ["JP"] = 0, ["US"] = 0, ["default"] = 0 };
        root["contentBadgeType"] ??= 1;
        root.Remove("originContentVersion");
        root.Remove("targetContentVersion");
        root["addcont"] = new JsonObject
        {
            ["serviceIdForSharing"] = new JsonArray(SharingServiceIds.Select(id => (JsonNode)JsonValue.Create(id)!).ToArray()),
        };

        string text = SortOrdinal(root).ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        text = text.Replace("\r\n", "\n", StringComparison.Ordinal)
                   .Replace("\n", "\r\n", StringComparison.Ordinal) + "\r\n";
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
    }

    /// <summary>
    /// Rewrites only the SDK fields of a source <c>param.json</c>: <c>sdkVersion</c> and the clamped
    /// <c>requiredSystemSoftwareVersion</c>. Every other field is preserved; the document is
    /// re-serialized with the same canonical conventions as <see cref="Build"/> (sorted keys, CRLF,
    /// no BOM). Used for an explicit SDK override without re-stamping the whole publisher document.
    /// </summary>
    /// <param name="sourceParamJson">Raw source <c>sce_sys/param.json</c> bytes.</param>
    /// <param name="executableVersion">Full 64-bit executable SDK identifier to apply.</param>
    public static byte[] ApplySdkOverride(ReadOnlySpan<byte> sourceParamJson, ulong executableVersion)
    {
        JsonNode node;
        try
        {
            node = JsonNode.Parse(sourceParamJson) ?? throw new InvalidDataException("sce_sys/param.json is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("sce_sys/param.json is not valid JSON.", ex);
        }
        if (node is not JsonObject root)
            throw new InvalidDataException("sce_sys/param.json must contain a JSON object.");

        ulong packageVersion = executableVersion & 0xFFFF000000000000UL;
        root["sdkVersion"] = VersionText(packageVersion);
        ulong required = Math.Max(Math.Min(HexVersion(root["requiredSystemSoftwareVersion"]), RequiredSystemSoftwareVersionCap), packageVersion);
        root["requiredSystemSoftwareVersion"] = VersionText(required);

        string text = SortOrdinal(root).ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        text = text.Replace("\r\n", "\n", StringComparison.Ordinal)
                   .Replace("\n", "\r\n", StringComparison.Ordinal) + "\r\n";
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
    }

    /// <summary>
    /// Rewrites only <c>applicationDrmType</c> in a source <c>param.json</c>. Every other field is
    /// preserved; the document is re-serialized with the same canonical conventions as
    /// <see cref="ApplySdkOverride"/> (sorted keys, CRLF, no BOM). Used for an explicit DRM override;
    /// the builder otherwise packages the source token verbatim.
    /// </summary>
    /// <param name="sourceParamJson">Raw source <c>sce_sys/param.json</c> bytes.</param>
    /// <param name="drmType">DRM token to stamp; for example <c>standard</c>.</param>
    public static byte[] ApplyDrmType(ReadOnlySpan<byte> sourceParamJson, string drmType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(drmType);
        JsonNode node;
        try
        {
            node = JsonNode.Parse(sourceParamJson) ?? throw new InvalidDataException("sce_sys/param.json is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("sce_sys/param.json is not valid JSON.", ex);
        }
        if (node is not JsonObject root)
            throw new InvalidDataException("sce_sys/param.json must contain a JSON object.");

        root["applicationDrmType"] = drmType;

        string text = SortOrdinal(root).ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
        text = text.Replace("\r\n", "\n", StringComparison.Ordinal)
                   .Replace("\n", "\r\n", StringComparison.Ordinal) + "\r\n";
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(text);
    }

    /// <summary>
    /// Resolves the SDK version from a source <c>eboot.bin</c>: an ELF <c>.sceversion</c> section, or
    /// the trailer appended to a publisher fake-SELF. Returns zero when nothing can be read.
    /// </summary>
    public static ulong ResolveSdkVersion(ReadOnlySpan<byte> eboot)
    {
        if (eboot.Length == 0)
            return 0;
        if (ProsperoSelfBuilder.IsElf(eboot))
            return TryGetSdkVersion(eboot, out ulong version) ? version : DefaultElfSdkVersion;
        if (ProsperoSelfBuilder.IsSelf(eboot) && TryGetSdkVersion(eboot, out ulong selfVersion))
            return selfVersion;
        return 0;
    }

    private static bool TryGetSdkVersion(ReadOnlySpan<byte> image, out ulong sdkVersion)
    {
        sdkVersion = 0;
        ReadOnlySpan<byte> records = ProsperoSelfBuilder.IsElf(image)
            ? FindElfSection(image, ".sceversion")
            : SelfTrailer(image);
        if (records.IsEmpty)
            return false;

        int major = -1, minor = -1;
        for (int i = 0; i + 4 <= records.Length;)
        {
            int declared = BinaryPrimitives.ReadUInt16LittleEndian(records[(i + 2)..]);
            int stride = declared + 4;
            if (declared < 17 || stride > records.Length - i)
                break;
            int payload = i + 5 + (declared - 17);
            int recordMajor = records[payload];
            int recordMinor = records[payload + 1];
            if (recordMajor > major || (recordMajor == major && recordMinor > minor))
            {
                major = recordMajor;
                minor = recordMinor;
            }
            i += stride;
        }

        if (major is < 0 or > 99 || minor is < 0 or > 99)
            return false;
        sdkVersion = ((ulong)PackedBcd(major) << 56) | ((ulong)PackedBcd(minor) << 48);
        return true;

        static byte PackedBcd(int value) => (byte)((value / 10 << 4) | (value % 10));
    }

    private static ReadOnlySpan<byte> SelfTrailer(ReadOnlySpan<byte> image)
    {
        if (!ProsperoSelfBuilder.IsSelf(image) || image.Length < 24)
            return ReadOnlySpan<byte>.Empty;
        ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(image[16..]);
        return offset <= (ulong)image.Length ? image[(int)offset..] : ReadOnlySpan<byte>.Empty;
    }

    private static ReadOnlySpan<byte> FindElfSection(ReadOnlySpan<byte> elf, string sectionName)
    {
        if (elf.Length < 64)
            return ReadOnlySpan<byte>.Empty;
        ulong sectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf[40..]);
        int entrySize = BinaryPrimitives.ReadUInt16LittleEndian(elf[58..]);
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(elf[60..]);
        int nameIndex = BinaryPrimitives.ReadUInt16LittleEndian(elf[62..]);
        if (sectionOffset == 0 || entrySize < 64 || sectionCount == 0 || nameIndex >= sectionCount || sectionOffset > int.MaxValue)
            return ReadOnlySpan<byte>.Empty;
        int start = (int)sectionOffset;
        if ((long)start + (long)sectionCount * entrySize > elf.Length)
            return ReadOnlySpan<byte>.Empty;

        ReadOnlySpan<byte> nameTable = SectionPayload(elf, start + nameIndex * entrySize);
        for (int i = 0; i < sectionCount; i++)
        {
            int header = start + i * entrySize;
            uint nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(elf[header..]);
            if (nameOffset >= (uint)nameTable.Length)
                continue;
            ReadOnlySpan<byte> name = nameTable[(int)nameOffset..];
            int terminator = name.IndexOf((byte)0);
            if (terminator >= 0 && name[..terminator].SequenceEqual(Encoding.ASCII.GetBytes(sectionName)))
                return SectionPayload(elf, header);
        }
        return ReadOnlySpan<byte>.Empty;

        static ReadOnlySpan<byte> SectionPayload(ReadOnlySpan<byte> source, int header)
        {
            ulong offset = BinaryPrimitives.ReadUInt64LittleEndian(source[(header + 24)..]);
            ulong size = BinaryPrimitives.ReadUInt64LittleEndian(source[(header + 32)..]);
            if (offset > int.MaxValue || size > int.MaxValue || offset + size > (ulong)source.Length)
                return ReadOnlySpan<byte>.Empty;
            return source.Slice((int)offset, (int)size);
        }
    }

    private static ulong HexVersion(JsonNode? node)
    {
        string? text = node?.GetValue<string>();
        if (text is null || !text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ||
            !ulong.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ulong value))
            return 0;
        return value;
    }

    private static string VersionText(ulong value) => $"0x{value:X16}".ToLowerInvariant();

    private static JsonNode SortOrdinal(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var sorted = new JsonObject();
                foreach (KeyValuePair<string, JsonNode?> pair in obj.OrderBy(p => p.Key, StringComparer.Ordinal))
                    sorted[pair.Key] = SortOrdinal(pair.Value);
                return sorted;
            case JsonArray array:
                var ordered = new JsonArray();
                foreach (JsonNode? item in array)
                    ordered.Add(SortOrdinal(item));
                return ordered;
            default:
                return node?.DeepClone() ?? JsonValue.Create((string?)null)!;
        }
    }
}
