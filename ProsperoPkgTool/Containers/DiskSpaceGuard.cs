namespace ProsperoPkgTool.Containers;

/// <summary>Outcome of a build-time free-space preflight.</summary>
public enum DiskSpaceStatus
{
    /// <summary>Enough free space with margin.</summary>
    Ok,

    /// <summary>Free space is close to the estimate; the build may be at risk.</summary>
    NearLimit,

    /// <summary>Not enough free space; the build cannot complete.</summary>
    Insufficient,
}

/// <summary>One volume's byte requirement for a build, with a human-readable label.</summary>
public readonly record struct SpaceRequirement(string Root, long Bytes, string What);

/// <summary>A free-space preflight result.</summary>
public sealed record DiskSpaceReport(
    DiskSpaceStatus Status, long RequiredBytes, long AvailableBytes, string Root, string What);

/// <summary>Thrown when a build cannot start because a target volume lacks free space.</summary>
public sealed class ProsperoInsufficientSpaceException : IOException
{
    public ProsperoInsufficientSpaceException(string message, long requiredBytes, long availableBytes, string root)
        : base(message)
    {
        RequiredBytes = requiredBytes;
        AvailableBytes = availableBytes;
        Root = root;
    }

    /// <summary>Free space the build needs (estimate plus safety margin), in bytes.</summary>
    public long RequiredBytes { get; }

    /// <summary>Free space actually available on <see cref="Root"/>, in bytes.</summary>
    public long AvailableBytes { get; }

    /// <summary>The volume root that is short of space.</summary>
    public string Root { get; }
}

/// <summary>
/// Estimates the peak disk a package build needs and checks it against free space. The file-backed
/// pipeline builds the inner image into the temp workspace and writes the outer PFS directly into the
/// final package (the CNT is metadata-only), so there is no full-image copy: the peak is roughly twice
/// the image size when the temp workspace and the output share a volume.
/// </summary>
public static class DiskSpaceGuard
{
    private const long Megabyte = 1024L * 1024;
    private const int SafetyPercent = 12;   // error threshold: estimate + 12%
    private const int WarnPercent = 25;     // near-limit threshold: estimate + 25%
    private const long HeadroomBytes = 512L * Megabyte;

    /// <summary>
    /// Estimates the bytes required on each affected volume. The temp workspace and the output
    /// collapse into one requirement when they share a volume (their peaks overlap).
    /// </summary>
    /// <param name="rawPayloadBytes">Sum of the inner files' payload lengths (upper bound for the inner image).</param>
    /// <param name="outputPath">Destination package path.</param>
    /// <param name="tempDirectory">Temp workspace parent; null uses the system temp folder.</param>
    public static IReadOnlyList<SpaceRequirement> Estimate(long rawPayloadBytes, string outputPath, string? tempDirectory)
    {
        if (rawPayloadBytes < 0)
            rawPayloadBytes = 0;

        // Peak model for the current (no-copy) pipeline: the inner image is built into the temp
        // workspace, and the outer PFS is written directly into the final package. The inner image can
        // be as large as the raw payload (compression only shrinks it), and the package is about the
        // same size again, so the peak is ~2x the payload on a shared volume. This deliberately does
        // not assume any compression ratio, so it never blocks a build that could fit.
        long inner = rawPayloadBytes + Math.Max(16 * Megabyte, rawPayloadBytes / 100);
        long outer = AlignUp(inner, ProsperoOuterPfsBuilder.BlockSize) + 32 * Megabyte;
        long output = ProsperoFihBuilder.HeaderRegionSize + outer + 64 * Megabyte; // + CNT metadata + SI
        long temp = inner + 64 * Megabyte;                                        // inner image + naps layout + slack

        string tempRoot = RootOf(tempDirectory ?? Path.GetTempPath());
        string outputRoot = RootOf(outputPath);

        if (string.Equals(tempRoot, outputRoot, StringComparison.OrdinalIgnoreCase))
            return [new SpaceRequirement(tempRoot, temp + output, "temp workspace + output")];

        return
        [
            new SpaceRequirement(tempRoot, temp, "temp workspace"),
            new SpaceRequirement(outputRoot, output, "output package"),
        ];
    }

    /// <summary>Checks the requirements, returning the worst status across the affected volumes.</summary>
    /// <param name="requirements">Per-volume byte requirements from <see cref="Estimate"/>.</param>
    /// <param name="freeSpaceProbe">Free-space lookup override (tests); null uses the real drive.</param>
    public static DiskSpaceReport Check(IReadOnlyList<SpaceRequirement> requirements, Func<string, long>? freeSpaceProbe = null)
    {
        ArgumentNullException.ThrowIfNull(requirements);
        DiskSpaceReport worst = new(DiskSpaceStatus.Ok, 0, long.MaxValue, string.Empty, string.Empty);

        foreach (SpaceRequirement requirement in requirements)
        {
            long required = WithMargin(requirement.Bytes, SafetyPercent);
            long available = (freeSpaceProbe ?? AvailableFreeSpace)(requirement.Root);
            DiskSpaceStatus status = available < required
                ? DiskSpaceStatus.Insufficient
                : available < WithMargin(requirement.Bytes, WarnPercent)
                    ? DiskSpaceStatus.NearLimit
                    : DiskSpaceStatus.Ok;

            if (status > worst.Status)
                worst = new DiskSpaceReport(status, required, available, requirement.Root, requirement.What);
        }
        return worst;
    }

    /// <summary>A short human-readable description of a preflight result.</summary>
    public static string Describe(DiskSpaceReport report) => report.Status switch
    {
        DiskSpaceStatus.Insufficient =>
            $"not enough free space: need ~{Gigabytes(report.RequiredBytes)} GB on {report.Root} ({report.What}), " +
            $"have {Gigabytes(report.AvailableBytes)} GB free",
        DiskSpaceStatus.NearLimit =>
            $"low free space on {report.Root} ({report.What}): need ~{Gigabytes(report.RequiredBytes)} GB, " +
            $"have {Gigabytes(report.AvailableBytes)} GB free",
        _ => $"free space OK on {report.Root} ({report.What}): have {Gigabytes(report.AvailableBytes)} GB",
    };

    private static long WithMargin(long bytes, int percent)
    {
        try
        {
            return checked((long)Math.Ceiling(bytes * (1.0 + percent / 100.0)) + HeadroomBytes);
        }
        catch (OverflowException)
        {
            return long.MaxValue;
        }
    }

    private static long AvailableFreeSpace(string root)
    {
        try
        {
            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch (ArgumentException) { return long.MaxValue; }
        catch (IOException) { return long.MaxValue; }
        catch (UnauthorizedAccessException) { return long.MaxValue; }
    }

    private static string RootOf(string path)
    {
        try
        {
            return Path.GetPathRoot(Path.GetFullPath(path)) ?? path;
        }
        catch (ArgumentException) { return path; }
        catch (NotSupportedException) { return path; }
        catch (PathTooLongException) { return path; }
    }

    private static long AlignUp(long value, long block) =>
        value <= 0 ? block : (value + block - 1) / block * block;

    private static string Gigabytes(long bytes) =>
        (bytes / (double)(Megabyte * 1024)).ToString("N1", System.Globalization.CultureInfo.InvariantCulture);
}
