namespace ProsperoPkgTool;

/// <summary>
/// A progress snapshot for a long-running package operation. <see cref="Stage"/> names the
/// current phase (for example <c>Inner image</c> or <c>Outer PFS</c>); <see cref="Done"/> and
/// <see cref="Total"/> are in stage-native units (usually files or bytes). Reporting is a
/// read-only observation and never affects the produced bytes.
/// </summary>
/// <param name="Stage">Human-readable name of the current build/operation stage.</param>
/// <param name="Done">Units completed so far within the stage.</param>
/// <param name="Total">Total units expected for the stage, or 0 when unknown.</param>
public readonly record struct ProsperoBuildProgress(string Stage, long Done, long Total)
{
    /// <summary>
    /// Stable stage identifier; null for non-build reports (for example extraction). Consumers should
    /// use <see cref="ProsperoBuildStages"/> to name and order the stage rather than parsing
    /// <see cref="Stage"/>.
    /// </summary>
    public ProsperoBuildStage? StageId { get; init; }

    /// <summary>
    /// Bytes processed so far, when the stage can report a byte-accurate figure (inner image and
    /// outer PFS). Zero when only <see cref="Done"/>/<see cref="Total"/> units are available.
    /// </summary>
    public long BytesDone { get; init; }

    /// <summary>Total bytes for the stage, or 0 when a byte figure is not available.</summary>
    public long BytesTotal { get; init; }

    /// <summary>Path of the item currently being processed, when known.</summary>
    public string? CurrentPath { get; init; }

    /// <summary>Completion ratio in [0,1]; 0 when <see cref="Total"/> is unknown.</summary>
    public double Fraction => Total > 0 ? (double)Done / Total : 0;

    /// <summary>Byte completion ratio in [0,1]; 0 when <see cref="BytesTotal"/> is unknown.</summary>
    public double ByteFraction => BytesTotal > 0 ? (double)BytesDone / BytesTotal : 0;
}
