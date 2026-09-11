namespace ProsperoPkgTool.Compression;

/// <summary>
/// Kraken tuning parameters shared by the inner-image assembler, the PFSv3 container writer, and the
/// command line. The clean-room encoder is a fixed-subset encoder, so <see cref="DefaultLevel"/> is
/// recorded in the compressed-image header for parity but does not change the encoded bytes; the
/// thread count selects how many blocks are encoded concurrently.
/// </summary>
public static class KrakenTuning
{
    /// <summary>Default Kraken level recorded in the compressed-image header.</summary>
    public const int DefaultLevel = 7;

    /// <summary>Fastest accepted Kraken level.</summary>
    public const int MinLevel = -4;

    /// <summary>Highest accepted Kraken level.</summary>
    public const int MaxLevel = 9;

    /// <summary>Sentinel thread count meaning "use the processor count".</summary>
    public const int AutoThreads = 0;

    /// <summary>Upper bound applied to an explicit thread count.</summary>
    public const int MaxThreads = 256;

    /// <summary>Returns <paramref name="level"/> when it is a valid Kraken level; otherwise throws.</summary>
    public static int ValidateLevel(int level) => level is >= MinLevel and <= MaxLevel
        ? level
        : throw new ArgumentOutOfRangeException(nameof(level), level,
            $"Kraken level must be in the range {MinLevel}..{MaxLevel}.");

    /// <summary>Resolves a thread count: 0 selects the processor count; an explicit value is clamped.</summary>
    public static int ResolveThreads(int threads) => threads switch
    {
        < 0 => throw new ArgumentOutOfRangeException(nameof(threads), threads,
            "Kraken threads must be 0 (auto) or a positive count."),
        AutoThreads => Math.Clamp(Environment.ProcessorCount, 1, MaxThreads),
        _ => Math.Clamp(threads, 1, MaxThreads),
    };
}
