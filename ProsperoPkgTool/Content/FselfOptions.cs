namespace ProsperoPkgTool.Content;

/// <summary>
/// Options for <see cref="ProsperoSelfBuilder.MakeFself"/>. All values are optional; the defaults
/// reproduce the debug fake-SELF the reference scene tool writes for a plain 64-bit ELF module.
/// </summary>
public sealed class FselfOptions
{
    /// <summary>Application version stamped into the extended info (default 0).</summary>
    public ulong AppVersion { get; init; }

    /// <summary>Firmware version stamped into the extended info (default 0).</summary>
    public ulong FirmwareVersion { get; init; }

    /// <summary>Overrides the derived program authority id (PAID).</summary>
    public ulong? AuthorityId { get; init; }

    /// <summary>
    /// Module name used to synthesize a single <c>.sceversion</c> record when the input ELF is
    /// stripped. The caller supplies the module file name without its extension.
    /// </summary>
    public string? SceVersionName { get; init; }

    /// <summary>
    /// Eight-byte SDK record copied from the application's own <c>.sceversion</c> section and written
    /// twice into a synthesized library record. Required together with <see cref="SceVersionName"/>.
    /// </summary>
    public byte[]? SceVersionRecord { get; init; }
}
