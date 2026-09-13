using System.Buffers.Binary;
using System.Globalization;

namespace ProsperoPkgTool.Content;

/// <summary>
/// Known Prospero application SDK releases.
///
/// A release is identified by the full 64-bit executable SDK identifier stored as an eight-byte
/// big-endian tuple in a module's <c>.sceversion</c> record. Its top bytes are the BCD
/// <c>major.minor.micro.build</c> fields (for example <c>9.00.00.40</c> is <c>0x0900004000000411</c>).
/// The package metadata form keeps only the BCD major/minor (top 16 bits) for
/// <c>sce_sys/param.json sdkVersion</c>.
/// </summary>
public static class ProsperoSdkVersions
{
    /// <summary>One SDK release in the observed table.</summary>
    public readonly record struct Release(int Major, string Version, ulong ExecutableVersion)
    {
        /// <summary>The package metadata form of the identifier (BCD major/minor in the top 16 bits).</summary>
        public ulong PackageVersion => ToPackageVersion(ExecutableVersion);
    }

    // Observed Prospero application SDK identifiers (firmware-released SDK builds). The opaque low
    // dword is the release suffix that is not derivable from the dotted version string.
    private static readonly Release[] KnownReleases =
    {
        new(1, "1.00.00.50", 0x0100005000000001UL),
        new(2, "2.00.00.26", 0x0200002600000001UL),
        new(3, "3.00.00.27", 0x0300002700000211UL),
        new(4, "4.00.00.31", 0x0400003100000211UL),
        new(5, "5.00.00.33", 0x0500003300000001UL),
        new(6, "6.00.00.38", 0x0600003800000001UL),
        new(7, "7.00.00.38", 0x0700003800000311UL),
        new(8, "8.00.00.41", 0x0800004100000001UL),
        new(9, "9.00.00.40", 0x0900004000000411UL),
        new(10, "10.00.00.40", 0x1000004000000001UL),
        new(11, "11.00.00.40", 0x1100004000000001UL),
    };

    /// <summary>Known SDK releases in ascending major order.</summary>
    public static IReadOnlyList<Release> Releases { get; } = Array.AsReadOnly(KnownReleases);

    /// <summary>Finds the canonical release for a major SDK generation.</summary>
    public static bool TryGetByMajor(int major, out Release release)
    {
        foreach (Release candidate in KnownReleases)
        {
            if (candidate.Major == major)
            {
                release = candidate;
                return true;
            }
        }
        release = default;
        return false;
    }

    /// <summary>Returns the canonical release for a major SDK generation.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The major is not a known Prospero SDK generation.</exception>
    public static Release GetByMajor(int major) =>
        TryGetByMajor(major, out Release release)
            ? release
            : throw new ArgumentOutOfRangeException(nameof(major), major, "Unknown Prospero SDK major version.");

    /// <summary>Masks a full executable identifier to the package metadata form.</summary>
    public static ulong ToPackageVersion(ulong executableVersion) => executableVersion & 0xFFFF000000000000UL;

    /// <summary>The raw eight-byte big-endian tuple stored by a <c>.sceversion</c> record.</summary>
    public static byte[] BuildTuple(ulong executableVersion)
    {
        byte[] tuple = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(tuple, executableVersion);
        return tuple;
    }

    /// <summary>
    /// Parses an SDK option value: a bare major (<c>9</c>), a dotted version (<c>9.00</c>,
    /// <c>9.00.00.40</c>) or a raw 64-bit hex identifier (<c>0x0900004000000411</c>). A dotted value
    /// resolves through the release table by its major component.
    /// </summary>
    public static bool TryParse(string? text, out ulong executableVersion)
    {
        executableVersion = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ulong.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture, out executableVersion);
        }

        string majorText = text.Split('.')[0];
        if (!int.TryParse(majorText, NumberStyles.None, CultureInfo.InvariantCulture, out int major) || major <= 0)
            return false;
        if (!TryGetByMajor(major, out Release release))
            return false;
        executableVersion = release.ExecutableVersion;
        return true;
    }
}
