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
    /// <summary>Completion ratio in [0,1]; 0 when <see cref="Total"/> is unknown.</summary>
    public double Fraction => Total > 0 ? (double)Done / Total : 0;
}
