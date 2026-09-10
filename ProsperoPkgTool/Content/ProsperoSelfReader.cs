using System.Buffers.Binary;

namespace ProsperoPkgTool.Content;

/// <summary>
/// The extended-info record of a SELF container: the program authority id, program type, version
/// words, and the digest of the embedded ELF. Only the authority id is required for classification;
/// the remaining fields are exposed for diagnostics.
/// </summary>
/// <param name="AuthorityId">The program authority id (PAID); its top byte is the authority category.</param>
/// <param name="ProgramType">The secondary program-type word at extended-info +0x08.</param>
/// <param name="AppVersion">The application version word at +0x10.</param>
/// <param name="FirmwareVersion">The firmware version word at +0x18.</param>
/// <param name="ElfDigest">The 32-byte digest at +0x20 (SHA-256 of the embedded ELF for a fake-self).</param>
public sealed record ProsperoSelfExtInfo(
    ulong AuthorityId,
    ulong ProgramType,
    ulong AppVersion,
    ulong FirmwareVersion,
    byte[] ElfDigest);

/// <summary>
/// A parsed SELF container header plus its extended info, when present.
/// </summary>
/// <param name="ProgramType">The container program-type word at +0x08.</param>
/// <param name="HeaderSize">The header-region size at +0x0C.</param>
/// <param name="MetaSize">The metadata-region size at +0x0E.</param>
/// <param name="FileSize">The header-declared container file size at +0x10.</param>
/// <param name="SegmentCount">The segment-table entry count at +0x18.</param>
/// <param name="ExtInfo">The parsed extended info, or <see langword="null"/> when absent/unreadable.</param>
public sealed record ProsperoSelfImage(
    uint ProgramType,
    ushort HeaderSize,
    ushort MetaSize,
    ulong FileSize,
    ushort SegmentCount,
    ProsperoSelfExtInfo? ExtInfo);

/// <summary>
/// Clean-room structural reader for the SELF container our builder produces (see
/// <see cref="ProsperoSelfBuilder"/>). It validates the container header and segment table and
/// locates the extended-info record so callers can classify a module by its authority id without
/// decrypting or executing anything. It never verifies a signature.
/// </summary>
public static class ProsperoSelfReader
{
    private const int ContainerHeaderSize = 0x20;
    private const int SegmentEntrySize = 0x20;
    private const int ExtInfoSize = 0x40;
    private const int ElfHeaderSize = 0x40;
    private const int ElfProgramHeaderSize = 0x38;
    private const int ProgramHeaderCountOffset = 0x38;

    /// <summary>Returns whether the buffer begins with the PS5 or legacy Orbis SELF magic.</summary>
    public static bool IsSelf(ReadOnlySpan<byte> data) =>
        data.Length >= ContainerHeaderSize &&
        (BinaryPrimitives.ReadUInt32LittleEndian(data) is ProsperoSelfBuilder.Magic or ProsperoSelfBuilder.LegacyOrbisMagic);

    /// <summary>
    /// Parses a SELF container header and, when reachable, its extended-info record.
    /// </summary>
    /// <exception cref="InvalidDataException">The buffer is not a structurally valid SELF.</exception>
    public static ProsperoSelfImage Parse(ReadOnlySpan<byte> data)
    {
        if (!TryParse(data, out ProsperoSelfImage? image))
            throw new InvalidDataException("The buffer is not a structurally valid SELF container.");
        return image!;
    }

    /// <summary>
    /// Attempts to parse a SELF container header and its extended info. Returns <see langword="false"/>
    /// when the buffer is not a structurally valid SELF; the extended info may still be absent on a
    /// valid container.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out ProsperoSelfImage? image)
    {
        image = null;
        if (data.Length < ContainerHeaderSize || !IsSelf(data))
            return false;

        uint programType = BinaryPrimitives.ReadUInt32LittleEndian(data[0x08..]);
        ushort headerSize = BinaryPrimitives.ReadUInt16LittleEndian(data[0x0C..]);
        ushort metaSize = BinaryPrimitives.ReadUInt16LittleEndian(data[0x0E..]);
        ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(data[0x10..]);
        ushort segmentCount = BinaryPrimitives.ReadUInt16LittleEndian(data[0x18..]);

        if ((long)ContainerHeaderSize + (long)segmentCount * SegmentEntrySize > data.Length)
            return false;

        int embeddedElfOffset = ContainerHeaderSize + segmentCount * SegmentEntrySize;
        ProsperoSelfExtInfo? extInfo = TryReadExtInfo(data, embeddedElfOffset);

        image = new ProsperoSelfImage(programType, headerSize, metaSize, fileSize, segmentCount, extInfo);
        return true;
    }

    /// <summary>
    /// Reads the program authority id from a SELF container without allocating a full image. Returns
    /// <see langword="false"/> when the buffer is not a valid SELF or has no reachable extended info.
    /// </summary>
    public static bool TryReadAuthorityId(ReadOnlySpan<byte> data, out ulong authorityId)
    {
        authorityId = 0;
        if (!TryParse(data, out ProsperoSelfImage? image) || image!.ExtInfo is null)
            return false;
        authorityId = image.ExtInfo.AuthorityId;
        return true;
    }

    private static ProsperoSelfExtInfo? TryReadExtInfo(ReadOnlySpan<byte> data, int embeddedElfOffset)
    {
        if (embeddedElfOffset < 0 || embeddedElfOffset + ElfHeaderSize > data.Length)
            return null;
        if (!ProsperoSelfBuilder.IsElf(data[embeddedElfOffset..]))
            return null;

        ushort programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(
            data[(embeddedElfOffset + ProgramHeaderCountOffset)..]);
        int embeddedElfLength = ElfHeaderSize + programHeaderCount * ElfProgramHeaderSize;
        if (embeddedElfOffset + (long)embeddedElfLength > data.Length)
            return null;

        int extInfoOffset = AlignUp(embeddedElfOffset + embeddedElfLength, 0x10);
        if (extInfoOffset + ExtInfoSize > data.Length)
            return null;

        ulong authorityId = BinaryPrimitives.ReadUInt64LittleEndian(data[extInfoOffset..]);
        ulong programType = BinaryPrimitives.ReadUInt64LittleEndian(data[(extInfoOffset + 0x08)..]);
        ulong appVersion = BinaryPrimitives.ReadUInt64LittleEndian(data[(extInfoOffset + 0x10)..]);
        ulong firmwareVersion = BinaryPrimitives.ReadUInt64LittleEndian(data[(extInfoOffset + 0x18)..]);
        byte[] elfDigest = data.Slice(extInfoOffset + 0x20, 0x20).ToArray();
        return new ProsperoSelfExtInfo(authorityId, programType, appVersion, firmwareVersion, elfDigest);
    }

    private static int AlignUp(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);
}
