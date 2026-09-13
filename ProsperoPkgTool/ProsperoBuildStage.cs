namespace ProsperoPkgTool;

/// <summary>
/// Canonical, stable identifiers for the package-build pipeline stages. The engine is the single
/// source of truth for the stage vocabulary: consumers (including PS5PKGTool) should render
/// <see cref="ProsperoBuildStages.Name"/> and <see cref="ProsperoBuildStages.IndexOf"/> rather than
/// hardcoding their own step list.
/// </summary>
public enum ProsperoBuildStage
{
    /// <summary>Convert only: assembling the backup tree into a staging folder.</summary>
    Staging = 0,

    /// <summary>Build and compress the inner <c>pfs_image.dat</c>.</summary>
    InnerImage,

    /// <summary>Generate the NAPS file, block and integrity tables.</summary>
    Naps,

    /// <summary>Build the outer PFS (data write, hashing, AES-XTS).</summary>
    OuterPfs,

    /// <summary>Write the CNT bodies / metadata.</summary>
    Cnt,

    /// <summary>Finalize the FIH image and generate the SI segment.</summary>
    Finalize,
}

/// <summary>
/// The ordered build-stage vocabulary. <see cref="Build"/> is the canonical stage sequence reported
/// by <see cref="ProsperoDebugPackageBuilder"/> builds; <see cref="Staging"/> is a convert-only
/// prefix reported by <see cref="ProsperoPkgTool.Content.ProsperoBackupConverter"/>.
/// </summary>
public static class ProsperoBuildStages
{
    /// <summary>The ordered stages of a package build (excludes the convert-only staging prefix).</summary>
    public static IReadOnlyList<ProsperoBuildStage> Build { get; } =
    [
        ProsperoBuildStage.InnerImage,
        ProsperoBuildStage.Naps,
        ProsperoBuildStage.OuterPfs,
        ProsperoBuildStage.Cnt,
        ProsperoBuildStage.Finalize,
    ];

    /// <summary>Human-readable display name for a stage.</summary>
    public static string Name(ProsperoBuildStage stage) => stage switch
    {
        ProsperoBuildStage.Staging => "Staging",
        ProsperoBuildStage.InnerImage => "Inner image",
        ProsperoBuildStage.Naps => "NAPS",
        ProsperoBuildStage.OuterPfs => "Outer PFS",
        ProsperoBuildStage.Cnt => "CNT",
        ProsperoBuildStage.Finalize => "Finalize",
        _ => stage.ToString(),
    };

    /// <summary>
    /// Zero-based position of a build stage in <see cref="Build"/>, or -1 for
    /// <see cref="ProsperoBuildStage.Staging"/> (the convert-only prefix, not part of a build).
    /// </summary>
    public static int IndexOf(ProsperoBuildStage stage)
    {
        for (int i = 0; i < Build.Count; i++)
        {
            if (Build[i] == stage)
                return i;
        }
        return -1;
    }
}
