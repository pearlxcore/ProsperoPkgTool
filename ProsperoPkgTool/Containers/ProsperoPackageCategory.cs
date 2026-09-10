namespace ProsperoPkgTool.Containers;

/// <summary>
/// Semantic package category. This is intentionally independent from the FIH envelope
/// (debug/retail) because the same category can be finalized in either envelope.
/// </summary>
public enum ProsperoPackageCategory
{
    BaseGame,
    Application = BaseGame,
    UpdatePatch,
    DlcData,
    DlcNoData,
    OtherKnown,
    Unknown,
}

/// <summary>How strongly a category mapping is supported by clean-room evidence.</summary>
public enum PackageCategoryEvidence
{
    FixtureConfirmed,
    PubCmdConfirmed,
    Hypothesis,
    Unknown,
}

public sealed record ProsperoPackageCategoryInfo(
    ProsperoPackageCategory Category,
    uint RawContentType,
    PackageCategoryEvidence Evidence,
    string Description);

public static class ProsperoPackageCategories
{
    /// <summary>
    /// 0x20 is independently observed in retained prospero-pub-cmd base/debug and retail
    /// package artifacts as PS5 game/application data. Other values remain deliberately raw
    /// until an oracle establishes their full package semantics.
    /// </summary>
    public static ProsperoPackageCategoryInfo Classify(uint contentType) => contentType switch
    {
        0x20 => new(ProsperoPackageCategory.BaseGame, contentType,
            PackageCategoryEvidence.PubCmdConfirmed, "PS5 game/application data"),
        _ => new(ProsperoPackageCategory.Unknown, contentType,
            PackageCategoryEvidence.Unknown, "No clean-room category mapping is verified"),
    };
}
