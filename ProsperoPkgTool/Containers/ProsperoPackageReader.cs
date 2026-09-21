using System.Buffers.Binary;
using System.Text;

namespace ProsperoPkgTool.Containers;

public enum ProsperoPackageKind
{
    MetadataContainer,
    FinalizedDebug,
    FinalizedRetail,
    FinalizedPatchDebug,
}

public sealed record ProsperoFihHeader(
    byte SignedByte,
    ushort FormatVersion,
    ulong PfsOffset,
    ulong PfsSize,
    ulong CntOffset);

/// <summary>
/// Structural fields from the leading layer-image header observed on debug/nwonly patch packages.
/// This describes physical package geometry only; it is not a patch-writer contract.
/// </summary>
public sealed record ProsperoLihHeader(
    ushort FormatVersion,
    uint Unknown10High,
    ulong FihOffset,
    ulong PackageSize,
    ulong LihSize,
    ulong FihSize,
    ulong CntOffset,
    ulong CntSize,
    ulong SiOffset,
    ulong SiSize);

public sealed record ProsperoCntHeader(
    ushort Version,
    ushort Flags,
    uint Unk0C,
    uint EntryCount,
    ushort ScEntryCount,
    ushort EntryCount2,
    uint EntryTableOffset,
    uint MainEntDataSize,
    ulong BodyOffset,
    ulong BodySize,
    string ContentId,
    uint DrmType,
    uint ContentType,
    uint ContentFlags);

public sealed record ProsperoPackageSegment(string Name, long Offset, long Size);

public sealed record ProsperoCntEntry(
    uint Id,
    uint NameOffset,
    uint Flags1,
    uint Flags2,
    uint DataOffset,
    uint DataSize,
    string? Name)
{
    public bool IsEncrypted => (Flags1 & 0x80000000) != 0;

    public string DisplayName => Name ?? Id switch
    {
        0x00000001 => "digests",
        0x00000010 => "entry-keys",
        0x00000020 => "image-key",
        0x00000080 => "general-digests",
        0x00000100 => "metas",
        0x00000200 => "entry-names",
        0x0000040A => "imagedigs.dat",
        0x00001001 => "playgo-chunk.dat",
        0x00001200 => "icon0.png",
        0x00001220 => "pic0.png",
        0x00001240 => "snd0.at9",
        0x00001280 => "icon0.dds",
        0x000012A0 => "pic0.dds",
        0x000012C0 => "pic1.dds",
        0x00002000 => "param.json",
        0x00002010 => "playgo-hash-table.dat",
        0x00002011 => "playgo-ficm.dat",
        0x00002060 => "pic2.dds",
        _ => "(unnamed)",
    };
}

public sealed record ProsperoPackageInspection(
    string Path,
    long FileSize,
    ProsperoPackageKind Kind,
    ProsperoFihHeader? Fih,
    ProsperoCntHeader Cnt,
    IReadOnlyList<ProsperoCntEntry> Entries,
    IReadOnlyList<ProsperoPackageSegment> Segments,
    VerificationResult Structure,
    ProsperoLihHeader? Lih = null);

public static class ProsperoPackageInspectionExtensions
{
    /// <summary>Semantic category derived without conflating it with the FIH envelope.</summary>
    public static ProsperoPackageCategoryInfo Category(this ProsperoPackageInspection inspection)
    {
        ArgumentNullException.ThrowIfNull(inspection);
        return ProsperoPackageCategories.Classify(inspection.Cnt.ContentType);
    }
}

public static class ProsperoPackageReader
{
    private static ReadOnlySpan<byte> FihMagic => [0x7F, (byte)'F', (byte)'I', (byte)'H'];
    private static ReadOnlySpan<byte> LihMagic => [0x7F, (byte)'L', (byte)'I', (byte)'H'];
    private static ReadOnlySpan<byte> CntMagic => [0x7F, (byte)'C', (byte)'N', (byte)'T'];
    private const int FihRegionSize = 0x10000;
    private const int CntHeaderSize = 0x5A0;
    private const int SegmentAlignment = 0x10000;

    public static ProsperoPackageInspection Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length < 4)
            throw new InvalidDataException("File is too small to contain a PS5 package header.");

        Span<byte> magic = stackalloc byte[4];
        ReadExactlyAt(stream, 0, magic);
        return magic.SequenceEqual(FihMagic)
            ? ReadFinalized(stream, fullPath)
            : magic.SequenceEqual(LihMagic)
                ? ReadPatch(stream, fullPath)
            : magic.SequenceEqual(CntMagic)
                ? ReadMetadata(stream, fullPath)
                : throw new InvalidDataException("Unknown package magic; expected FIH, LIH, or CNT.");
    }

    private static ProsperoPackageInspection ReadPatch(FileStream stream, string path)
    {
        if (stream.Length < FihRegionSize)
            throw new InvalidDataException("Patch image is smaller than the 0x10000-byte LIH region.");

        byte[] header = new byte[0x50];
        ReadExactlyAt(stream, 0, header);
        var lih = new ProsperoLihHeader(
            BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x06, 2)),
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x14, 4)),
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x10, 4)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x18, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x20, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x28, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x30, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x38, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x40, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x48, 8)));

        var issues = new List<VerificationIssue>();
        if (lih.FormatVersion != 1)
            issues.Add(Error("LIH_VERSION", $"LIH format version is {lih.FormatVersion}; expected 1."));
        if (lih.LihSize != FihRegionSize || lih.FihOffset != lih.LihSize)
            issues.Add(Error("LIH_FIH_OFFSET", "LIH does not place the FIH immediately after its 0x10000-byte region."));
        if (!TryRange(lih.FihOffset, lih.FihSize, stream.Length, out long fihOffset, out long fihSize))
            throw new InvalidDataException("LIH FIH segment lies outside the package.");
        if (lih.PackageSize != (ulong)stream.Length)
            issues.Add(Error("LIH_PACKAGE_SIZE", "LIH package size does not match the physical file length."));
        if (!TryRange(lih.CntOffset, lih.CntSize, stream.Length, out long cntOffset, out long cntSize))
            throw new InvalidDataException("LIH SC/CNT segment lies outside the package.");
        if (!TryRange(lih.SiOffset, lih.SiSize, stream.Length, out long siOffset, out long siSize))
            throw new InvalidDataException("LIH SI segment lies outside the package.");

        long pfsOffset = checked(fihOffset + fihSize);
        long pfsSize = checked(cntOffset - pfsOffset);
        if (pfsSize < 0)
            throw new InvalidDataException("LIH SC/CNT begins before the end of FIH.");
        if (siOffset != cntOffset + cntSize)
            issues.Add(Error("LIH_SEGMENT_GAP", "LIH SI offset does not immediately follow SC/CNT."));
        if (siOffset + siSize != stream.Length)
            issues.Add(Error("LIH_SI_SIZE", "LIH SI segment does not end at the physical package length."));

        Span<byte> fihPrefix = stackalloc byte[8];
        ReadExactlyAt(stream, fihOffset, fihPrefix);
        if (!fihPrefix[..4].SequenceEqual(FihMagic))
            throw new InvalidDataException("LIH FIH segment does not begin with FIH magic.");
        byte signedByte = fihPrefix[5];
        if (signedByte != 0x00)
            throw ProsperoErrorInfo.Unsupported($"Unsupported patch FIH signed byte 0x{signedByte:X2}; only observed debug patches are supported structurally.");

        var fih = new ProsperoFihHeader(
            signedByte,
            BinaryPrimitives.ReadUInt16LittleEndian(fihPrefix[6..]),
            (ulong)pfsOffset,
            (ulong)pfsSize,
            (ulong)cntOffset);
        ProsperoCntHeader cnt = ReadCntHeader(stream, cntOffset);
        IReadOnlyList<ProsperoCntEntry> entries = ReadCntEntries(stream, cntOffset, cnt, issues, out long cntLogicalSize);
        if (cntLogicalSize > cntSize)
            issues.Add(Error("CNT_RANGE", "CNT entry payloads extend beyond the LIH SC/CNT segment."));
        if (siSize >= 4)
        {
            Span<byte> zipMagic = stackalloc byte[4];
            ReadExactlyAt(stream, siOffset, zipMagic);
            if (!(zipMagic[0] == (byte)'P' && zipMagic[1] == (byte)'K' && zipMagic[2] == 0x03 && zipMagic[3] == 0x04))
                issues.Add(new VerificationIssue("SI_MAGIC", "LIH SI segment does not begin with a ZIP local-file header.", false));
        }

        IReadOnlyList<ProsperoPackageSegment> segments =
        [
            new("LIH", 0, checked((long)lih.LihSize)),
            new("FIH", fihOffset, fihSize),
            new("PFS", pfsOffset, pfsSize),
            new("SC", cntOffset, cntSize),
            new("SI", siOffset, siSize),
        ];
        return new ProsperoPackageInspection(path, stream.Length, ProsperoPackageKind.FinalizedPatchDebug,
            fih, cnt, entries, segments, new VerificationResult(issues.All(issue => !issue.IsError), issues), lih);
    }

    private static ProsperoPackageInspection ReadFinalized(FileStream stream, string path)
    {
        if (stream.Length < FihRegionSize)
            throw new InvalidDataException("Finalized image is smaller than the 0x10000-byte FIH region.");

        byte[] header = new byte[0x100];
        ReadExactlyAt(stream, 0, header);
        byte signedByte = header[0x05];
        ProsperoPackageKind kind = signedByte switch
        {
            0x00 => ProsperoPackageKind.FinalizedDebug,
            0x80 => ProsperoPackageKind.FinalizedRetail,
            _ => throw ProsperoErrorInfo.Unsupported($"Unsupported FIH signed byte 0x{signedByte:X2}.")
        };
        var fih = new ProsperoFihHeader(
            signedByte,
            BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x06, 2)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x10, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x18, 8)),
            BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x58, 8)));

        var issues = new List<VerificationIssue>();
        if (fih.FormatVersion != 3)
            issues.Add(Error("FIH_VERSION", $"FIH format version is {fih.FormatVersion}; expected 3."));
        if (fih.PfsOffset != FihRegionSize)
            issues.Add(Error("PFS_OFFSET", $"PFS starts at 0x{fih.PfsOffset:X}; expected 0x{FihRegionSize:X}."));
        if (!TryRange(fih.PfsOffset, fih.PfsSize, stream.Length, out long pfsOffset, out long pfsSize))
            issues.Add(Error("PFS_RANGE", "PFS segment lies outside the package."));
        if (fih.CntOffset > (ulong)Math.Max(0, stream.Length - CntHeaderSize))
            throw new InvalidDataException("Embedded CNT header lies outside the package.");
        if (TryRange(fih.PfsOffset, fih.PfsSize, stream.Length, out pfsOffset, out pfsSize) &&
            (ulong)(pfsOffset + pfsSize) != fih.CntOffset)
            issues.Add(Error("SEGMENT_GAP", "PFS end does not equal the embedded CNT offset."));

        long cntOffset = checked((long)fih.CntOffset);
        ProsperoCntHeader cnt = ReadCntHeader(stream, cntOffset);
        IReadOnlyList<ProsperoCntEntry> entries = ReadCntEntries(stream, cntOffset, cnt, issues, out long cntLogicalSize);
        long cntSize = AlignUp(cntLogicalSize, SegmentAlignment);
        if (!IsRangeWithin(cntOffset, cntSize, stream.Length))
        {
            issues.Add(Error("CNT_RANGE", "Aligned embedded CNT segment lies outside the package."));
            cntSize = Math.Max(0, stream.Length - cntOffset);
        }

        long siOffset = checked(cntOffset + cntSize);
        long siSize = Math.Max(0, stream.Length - siOffset);
        if (siSize >= 4)
        {
            Span<byte> zipMagic = stackalloc byte[4];
            ReadExactlyAt(stream, siOffset, zipMagic);
            if (!(zipMagic[0] == (byte)'P' && zipMagic[1] == (byte)'K' && zipMagic[2] == 0x03 && zipMagic[3] == 0x04))
                issues.Add(new VerificationIssue("SI_MAGIC", "Trailing SI segment does not begin with a ZIP local-file header.", false));
        }
        else if (siSize > 0)
        {
            issues.Add(Error("SI_RANGE", "Trailing SI segment is too small to contain a ZIP header."));
        }
        else
        {
            issues.Add(new VerificationIssue("SI_MISSING", "Finalized image has no trailing SI segment.", false));
        }

        var segments = new List<ProsperoPackageSegment>
        {
            new("FIH", 0, FihRegionSize),
            new("PFS", pfsOffset, pfsSize),
            new("SC", cntOffset, cntSize),
            new("SI", siOffset, siSize),
        };
        return new ProsperoPackageInspection(path, stream.Length, kind, fih, cnt, entries, segments,
            new VerificationResult(issues.All(issue => !issue.IsError), issues));
    }

    private static ProsperoPackageInspection ReadMetadata(FileStream stream, string path)
    {
        ProsperoCntHeader cnt = ReadCntHeader(stream, 0);
        var issues = new List<VerificationIssue>();
        if (cnt.EntryTableOffset < CntHeaderSize)
            issues.Add(Error("ENTRY_TABLE_OFFSET", "CNT entry table overlaps the fixed header."));
        IReadOnlyList<ProsperoCntEntry> entries = ReadCntEntries(stream, 0, cnt, issues, out long logicalSize);
        if (logicalSize > stream.Length)
            issues.Add(Error("CNT_RANGE", "CNT body lies outside the file."));
        return new ProsperoPackageInspection(
            path,
            stream.Length,
            ProsperoPackageKind.MetadataContainer,
            null,
            cnt,
            entries,
            [new ProsperoPackageSegment("CNT", 0, stream.Length)],
            new VerificationResult(issues.All(issue => !issue.IsError), issues));
    }

    private static ProsperoCntHeader ReadCntHeader(FileStream stream, long offset)
    {
        if (!IsRangeWithin(offset, CntHeaderSize, stream.Length))
            throw new InvalidDataException("CNT header lies outside the package.");
        byte[] header = new byte[CntHeaderSize];
        ReadExactlyAt(stream, offset, header);
        if (!header.AsSpan(0, 4).SequenceEqual(CntMagic))
            throw new InvalidDataException("Embedded container does not have CNT magic.");

        // CNT header field map (big-endian), verified byte-exact against a real
        // Sony-built debug package and FINDINGS.md §04:
        //   0x04 u16 version (2)        0x06 u16 flags (1)
        //   0x0C u32 constant 0x0C (NOT the entry count)
        //   0x10 u32 entry count (13)   0x14 u16 sc-entry count (6)  0x16 u16 entry count 2 (13)
        //   0x18 u32 entry-table offset (0x3560)   0x1C u32 main-ent data size (0x18A0)
        //   0x20 u64 body offset (0x2000)          0x28 u64 body size (0x4E0)
        //   0x40 content id (0x24 = 36 bytes, ASCII NUL-padded; the field is 36 bytes,
        //      not 0x30 — FINDINGS.md line 235)
        //   0x70 drm type  0x74 content type  0x78 content flags
        return new ProsperoCntHeader(
            BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(0x04, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(0x06, 2)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x0C, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x10, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(0x14, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(0x16, 2)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x18, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x1C, 4)),
            BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(0x20, 8)),
            BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(0x28, 8)),
            ReadAscii(header.AsSpan(0x40, 0x24)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x70, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x74, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0x78, 4)));
    }

    private static IReadOnlyList<ProsperoCntEntry> ReadCntEntries(
        FileStream stream,
        long cntOffset,
        ProsperoCntHeader cnt,
        ICollection<VerificationIssue> issues,
        out long logicalSize)
    {
        const int entrySize = 0x20;
        // The container's extent is the highest end offset across all entry payloads
        // (FINDINGS.md §04: entries can extend well past the fixed "body size" fields,
        // which describe only the header/metas region). We clamp to the file size and
        // also guard against a maliciously large entry count.
        long cntAvailable = Math.Max(0, stream.Length - cntOffset);
        if (cnt.EntryCount > 0x10000)
        {
            issues.Add(Error("ENTRY_COUNT", $"CNT entry count {cnt.EntryCount} exceeds the safety limit."));
            logicalSize = Math.Min(cntAvailable, CntHeaderSize);
            return [];
        }
        long tableSize = checked((long)cnt.EntryCount * entrySize);
        if (!IsRangeWithin(cnt.EntryTableOffset, tableSize, cntAvailable) ||
            !IsRangeWithin(checked(cntOffset + (long)cnt.EntryTableOffset), tableSize, stream.Length))
        {
            issues.Add(Error("ENTRY_TABLE_RANGE", "CNT entry table lies outside the container."));
            logicalSize = Math.Min(cntAvailable, CntHeaderSize);
            return [];
        }

        var entries = new List<ProsperoCntEntry>((int)cnt.EntryCount);
        byte[] table = new byte[tableSize];
        ReadExactlyAt(stream, checked(cntOffset + cnt.EntryTableOffset), table);

        long maxEnd = CntHeaderSize;
        for (int index = 0; index < cnt.EntryCount; index++)
        {
            ReadOnlySpan<byte> record = table.AsSpan(index * entrySize, entrySize);
            var entry = new ProsperoCntEntry(
                BinaryPrimitives.ReadUInt32BigEndian(record[0x00..]),
                BinaryPrimitives.ReadUInt32BigEndian(record[0x04..]),
                BinaryPrimitives.ReadUInt32BigEndian(record[0x08..]),
                BinaryPrimitives.ReadUInt32BigEndian(record[0x0C..]),
                BinaryPrimitives.ReadUInt32BigEndian(record[0x10..]),
                BinaryPrimitives.ReadUInt32BigEndian(record[0x14..]),
                null);
            if (!IsRangeWithin(entry.DataOffset, entry.DataSize, cntAvailable))
            {
                issues.Add(Error("ENTRY_DATA_RANGE", $"CNT entry 0x{entry.Id:X8} data lies outside the container."));
            }
            else
            {
                long end = checked((long)entry.DataOffset + (long)entry.DataSize);
                if (end > maxEnd)
                    maxEnd = end;
            }
            entries.Add(entry);
        }
        logicalSize = maxEnd;

        int nameTableIndex = entries.FindIndex(entry => entry.Id == 0x00000200);
        if (nameTableIndex < 0)
            return entries;
        ProsperoCntEntry nameTableEntry = entries[nameTableIndex];
        if (nameTableEntry.DataSize == 0 || nameTableEntry.DataSize > 16 * 1024 * 1024 ||
            !IsRangeWithin(nameTableEntry.DataOffset, nameTableEntry.DataSize, cntAvailable))
            return entries;

        byte[] names = new byte[nameTableEntry.DataSize];
        ReadExactlyAt(stream, checked(cntOffset + nameTableEntry.DataOffset), names);
        for (int index = 0; index < entries.Count; index++)
        {
            ProsperoCntEntry entry = entries[index];
            if (entry.NameOffset == uint.MaxValue || entry.NameOffset >= names.Length)
                continue;
            ReadOnlySpan<byte> tail = names.AsSpan((int)entry.NameOffset);
            int terminator = tail.IndexOf((byte)0);
            if (terminator < 0)
            {
                issues.Add(Error("ENTRY_NAME", $"CNT entry 0x{entry.Id:X8} name is not NUL-terminated."));
                continue;
            }
            string name = Encoding.UTF8.GetString(tail[..terminator]);
            entries[index] = entry with { Name = name.Length == 0 ? null : name };
        }
        return entries;
    }

    private static bool TryRange(ulong offset, ulong size, long fileSize, out long resultOffset, out long resultSize)
    {
        resultOffset = offset <= long.MaxValue ? (long)offset : 0;
        resultSize = size <= long.MaxValue ? (long)size : 0;
        return offset <= long.MaxValue && size <= long.MaxValue && IsRangeWithin(resultOffset, resultSize, fileSize);
    }

    private static bool IsRangeWithin(long offset, long size, long fileSize) =>
        offset >= 0 && size >= 0 && offset <= fileSize && size <= fileSize - offset;

    private static long AlignUp(long value, int alignment)
    {
        long remainder = value % alignment;
        return remainder == 0 ? value : checked(value + alignment - remainder);
    }

    private static string ReadAscii(ReadOnlySpan<byte> bytes)
    {
        int length = bytes.IndexOf((byte)0);
        if (length < 0)
            length = bytes.Length;
        return Encoding.ASCII.GetString(bytes[..length]);
    }

    private static void ReadExactlyAt(FileStream stream, long offset, Span<byte> buffer)
    {
        stream.Position = offset;
        stream.ReadExactly(buffer);
    }

    private static VerificationIssue Error(string code, string message) => new(code, message, true);
}
