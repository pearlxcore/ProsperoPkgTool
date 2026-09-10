namespace ProsperoPkgTool.Containers;

/// <summary>Resolved table policy for one CNT entry: the two flag words and whether its name is stored.</summary>
public readonly record struct ProsperoCntEntryProfile(uint Flags1, uint Flags2, bool IncludeName);

/// <summary>
/// Clean-room resolver for the CNT meta-row flags, encryption-key index and fixed-entry naming rule.
/// Encrypted/protected entries carry <c>0x80000000 | keyIndex &lt;&lt; 12</c>; publisher body entries
/// carry <c>0x08000000</c>; the six SC entries and param.json are fixed. A nested <c>npbind.dat</c>
/// (under <c>uds/</c> or <c>trophy2/</c>) is protected and named, unlike the flat one.
/// </summary>
public static class ProsperoCntEntryPolicy
{
    private const uint Encrypted = 0x80000000;
    private const uint PublisherData = 0x08000000;

    /// <summary>Resolves the profile for one entry id and sce_sys-relative name.</summary>
    /// <param name="id">The CNT entry id.</param>
    /// <param name="relativeName">The sce_sys-relative path (forward slashes), when known.</param>
    /// <param name="applicationDrmType">The param.json <c>applicationDrmType</c>, when known.</param>
    public static ProsperoCntEntryProfile Resolve(uint id, string? relativeName = null, string? applicationDrmType = null)
    {
        switch (id)
        {
            case (uint)CntEntryId.Digests:
                return new(0x40000000, 0, IncludeName: false);
            case (uint)CntEntryId.EntryKeys:
            case (uint)CntEntryId.ImageKey:
            case (uint)CntEntryId.GeneralDigests:
            case (uint)CntEntryId.Metas:
                return new(0x60000000, 0, IncludeName: false);
            case (uint)CntEntryId.EntryNames:
                return new(0x40000000, 0, IncludeName: false);
            case (uint)CntEntryId.LicenseDat:
                return Protected(3, includeName: false);
            case (uint)CntEntryId.LicenseInfo:
                return Protected(IsUpgradable(applicationDrmType) ? 4u : 2u, includeName: false);
            case (uint)CntEntryId.NptitleDat:
            case (uint)CntEntryId.NpbindDat:
            case (uint)CntEntryId.SelfinfoDat:
            case (uint)CntEntryId.ImageinfoDat:
            case (uint)CntEntryId.TargetDeltainfoDat:
            case (uint)CntEntryId.OriginDeltainfoDat:
            case (uint)CntEntryId.PsreservedDat:
                return Protected(3, includeName: false);
            case (uint)CntEntryId.ParamJson:
                return new(0, 0, IncludeName: true);
            default:
                if (IsNestedNpbind(relativeName))
                    return Protected(3, includeName: true);
                return new(PublisherData, 0, IncludeName: true);
        }
    }

    private static ProsperoCntEntryProfile Protected(uint keyIndex, bool includeName) =>
        new(Encrypted, keyIndex << 12, includeName);

    private static bool IsNestedNpbind(string? relativeName) =>
        relativeName is not null &&
        (relativeName.Equals("npbind.dat", StringComparison.OrdinalIgnoreCase) ||
         relativeName.EndsWith("/npbind.dat", StringComparison.OrdinalIgnoreCase));

    private static bool IsUpgradable(string? applicationDrmType) =>
        applicationDrmType?.Equals("upgradable", StringComparison.OrdinalIgnoreCase) ?? false;
}
