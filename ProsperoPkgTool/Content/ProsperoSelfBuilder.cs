using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ProsperoPkgTool.Content;

/// <summary>
/// Clean-room reader/producer for the SELF container used by PS5 executable modules. A debug
/// fake-SELF keeps the original ELF header and program headers, stores each loadable segment's
/// plaintext next to a zero-filled digest block, and carries an extended-info record whose digest is
/// the SHA-256 of the embedded ELF. The per-segment signature blocks and the program authority id
/// are the "fake" parts: the console accepts them in debug mode without a real signature.
///
/// Layout (little-endian scalars):
/// <code>
/// 0x0000  container header (0x20): magic 0xEEF51454, version/mode/endian/attr, program type,
///         header size (0x0C), metadata size (0x0E), file size (0x10), segment count (0x18), flags
/// 0x0020  segment table, 0x20 per entry: flags, file offset, file size, memory size
///         (content segments are paired: a digest block, then the plaintext data segment)
/// ...     embedded ELF header + program headers, copied verbatim
/// ...     extended info (0x40): authority id, program type, versions, SHA-256 of the ELF
/// ...     control region (0x30) and a zero-filled metadata footer carrying a 0x00010000 marker
/// ...     plaintext segment data
/// EOF     original non-allocated .sceversion section (or a synthesized record)
/// </code>
/// </summary>
public static class ProsperoSelfBuilder
{
    /// <summary>Container header magic for PS5 SELF images.</summary>
    public const uint Magic = 0xEEF51454;

    /// <summary>Legacy Orbis SELF magic, accepted by the reader.</summary>
    public const uint LegacyOrbisMagic = 0x1D3D154F;

    private const int ContainerHeaderSize = 0x20;
    private const int SegmentEntrySize = 0x20;
    private const int ExtInfoSize = 0x40;
    private const int ControlRegionSize = 0x30;
    private const int MetaBlockSize = 0x50;
    private const int MetaSignatureSize = 0x220;
    private const int DigestSize = 0x20;
    private const int SignedBlockSize = 0x4000;
    private const int FooterMarkerOffset = 0x30;
    private const uint DefaultProgramType = 0x10000101;

    private const int ElfHeaderSize = 0x40;
    private const int ElfProgramHeaderSize = 0x38;
    private const int ExInfoByteOffset = 0x3F00;
    private const int SectionHeaderSize = 0x40;

    private const uint PtLoad = 0x00000001;
    private const uint PtModuleData = 0x61000000;
    private const uint PtRelro = 0x61000010;
    private const uint PtComment = 0x6FFFFF00;

    /// <summary>Returns whether the buffer begins with a SELF container header (PS5 or legacy).</summary>
    public static bool IsSelf(ReadOnlySpan<byte> data)
    {
        if (data.Length < ContainerHeaderSize)
            return false;
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        return magic is Magic or LegacyOrbisMagic;
    }

    /// <summary>Returns whether the buffer begins with an ELF header.</summary>
    public static bool IsElf(ReadOnlySpan<byte> data) =>
        data.Length >= ElfHeaderSize &&
        data[0] == 0x7F && data[1] == (byte)'E' && data[2] == (byte)'L' && data[3] == (byte)'F';

    /// <summary>
    /// Builds a debug fake-SELF from a plaintext 64-bit ELF module.
    /// </summary>
    /// <param name="elf">The input ELF file bytes.</param>
    /// <param name="options">Version/authority overrides and optional <c>.sceversion</c> synthesis.</param>
    /// <exception cref="ArgumentException">The input is not a supported 64-bit ELF module.</exception>
    public static byte[] MakeFself(byte[] elf, FselfOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(elf);
        options ??= new FselfOptions();
        if (!IsElf(elf))
            throw new ArgumentException("Input is not an ELF file.", nameof(elf));
        if (elf[4] != 2)
            throw new ArgumentException("Only 64-bit ELF modules are supported.", nameof(elf));

        ushort eType = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x10));
        ulong programHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(0x20));
        ushort programHeaderEntrySize = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x36));
        ushort programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x38));
        if (programHeaderOffset != ElfHeaderSize)
            throw new ArgumentException(
                $"The ELF program-header table must follow the ELF header at 0x{ElfHeaderSize:X} (e_phoff is 0x{programHeaderOffset:X}).",
                nameof(elf));
        if (programHeaderEntrySize != ElfProgramHeaderSize)
            throw new ArgumentException($"Unexpected ELF program-header size {programHeaderEntrySize}.", nameof(elf));
        if (ElfHeaderSize + (long)programHeaderCount * ElfProgramHeaderSize > elf.Length)
            throw new ArgumentException("ELF program headers overrun the file.", nameof(elf));

        List<SelectedSegment> selected = SelectSegments(elf, ElfHeaderSize, programHeaderCount);
        if (selected.Count == 0)
            throw new ArgumentException("The ELF has no loadable segment content.", nameof(elf));

        int segmentCount = selected.Count * 2;
        int segmentTableEnd = ContainerHeaderSize + segmentCount * SegmentEntrySize;
        int embeddedElfLength = ElfHeaderSize + programHeaderCount * ElfProgramHeaderSize;
        int extInfoOffset = AlignUp(segmentTableEnd + embeddedElfLength, 0x10);
        int headerSize = extInfoOffset + ExtInfoSize + ControlRegionSize;
        int metaSize = segmentCount * MetaBlockSize + MetaBlockSize + MetaSignatureSize;
        int dataStart = headerSize + metaSize;
        if (headerSize > ushort.MaxValue || metaSize > ushort.MaxValue)
            throw new ArgumentException(
                $"The ELF has too many segments to fake-sign (header 0x{headerSize:X}, meta 0x{metaSize:X} exceed the 16-bit container fields).",
                nameof(elf));

        int[] digestSizes = new int[selected.Count];
        int[] segmentOffsets = new int[segmentCount];
        int cursor = dataStart;
        for (int i = 0; i < selected.Count; i++)
        {
            digestSizes[i] = (int)((selected[i].FileSize + SignedBlockSize - 1) / SignedBlockSize) * DigestSize;
            segmentOffsets[i * 2] = cursor;
            cursor += digestSizes[i];
            segmentOffsets[i * 2 + 1] = cursor;
            cursor += selected[i].FileSize;
            if (i + 1 < selected.Count)
                cursor = AlignUp(cursor, 0x10);
        }
        int fileSize = cursor;

        ReadOnlySpan<byte> embeddedSceVersion = FindElfSection(elf, ".sceversion");
        byte[]? synthesized = null;
        if (embeddedSceVersion.IsEmpty &&
            !string.IsNullOrWhiteSpace(options.SceVersionName) &&
            options.SceVersionRecord is { Length: 8 })
        {
            synthesized = BuildSceVersionRecord(options.SceVersionName!, options.SceVersionRecord);
        }
        ReadOnlySpan<byte> trailer = synthesized ?? embeddedSceVersion;

        byte[] output = new byte[fileSize + trailer.Length];
        Span<byte> span = output;

        BinaryPrimitives.WriteUInt32LittleEndian(span, Magic);
        span[0x04] = 0x10;
        span[0x05] = 0x01;
        span[0x06] = 0x01;
        span[0x07] = 0x12;
        BinaryPrimitives.WriteUInt32LittleEndian(span[0x08..], DefaultProgramType);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x0C..], (ushort)headerSize);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x0E..], (ushort)metaSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[0x10..], (ulong)fileSize);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x18..], (ushort)segmentCount);
        BinaryPrimitives.WriteUInt16LittleEndian(span[0x1A..], 0x0032);

        for (int i = 0; i < selected.Count; i++)
        {
            int digestEntry = ContainerHeaderSize + i * 2 * SegmentEntrySize;
            int dataEntry = ContainerHeaderSize + (i * 2 + 1) * SegmentEntrySize;
            ulong digestFlags = ((ulong)(i * 2 + 1) << 20) | 0x10004;
            WriteSegment(span, digestEntry, digestFlags, segmentOffsets[i * 2], digestSizes[i], digestSizes[i]);
            ulong dataFlags = ((ulong)selected[i].ProgramHeaderIndex << 20) | 0x2804;
            WriteSegment(span, dataEntry, dataFlags, segmentOffsets[i * 2 + 1], selected[i].FileSize, selected[i].FileSize);
        }

        elf.AsSpan(0, embeddedElfLength).CopyTo(span[segmentTableEnd..]);

        ulong authorityId = options.AuthorityId ?? DeriveAuthorityId(elf, eType);
        BinaryPrimitives.WriteUInt64LittleEndian(span[extInfoOffset..], authorityId);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(extInfoOffset + 0x08)..], 1);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(extInfoOffset + 0x10)..], options.AppVersion);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(extInfoOffset + 0x18)..], options.FirmwareVersion);
        SHA256.HashData(elf).CopyTo(span[(extInfoOffset + 0x20)..]);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(extInfoOffset + ExtInfoSize)..], 3);

        int footerMarker = headerSize + segmentCount * MetaBlockSize + FooterMarkerOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(span[footerMarker..], 0x00010000);

        for (int i = 0; i < selected.Count; i++)
            elf.AsSpan(selected[i].FileOffset, selected[i].FileSize).CopyTo(span[segmentOffsets[i * 2 + 1]..]);

        trailer.CopyTo(span[fileSize..]);
        return output;
    }

    /// <summary>
    /// Reads the first eight-byte SDK/library version tuple from an ELF <c>.sceversion</c> section or
    /// from the trailer appended to a publisher fake-SELF.
    /// </summary>
    public static bool TryGetSceVersionRecord(byte[] image, out byte[] record)
    {
        ArgumentNullException.ThrowIfNull(image);
        ReadOnlySpan<byte> records = GetSceVersionRecords(image);
        if (records.Length >= 4)
        {
            int declaredSize = BinaryPrimitives.ReadUInt16LittleEndian(records[2..]);
            if (declaredSize >= 17 && declaredSize + 4 <= records.Length)
            {
                int start = declaredSize - 12;
                record = records.Slice(start, 8).ToArray();
                return true;
            }
        }
        record = [];
        return false;
    }

    private static ReadOnlySpan<byte> GetSceVersionRecords(byte[] image)
    {
        if (IsElf(image))
            return FindElfSection(image, ".sceversion");
        if (IsSelf(image))
        {
            ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(0x10));
            if (fileSize <= (ulong)image.LongLength)
                return image.AsSpan((int)fileSize);
        }
        return ReadOnlySpan<byte>.Empty;
    }

    private static byte[] BuildSceVersionRecord(string moduleName, ReadOnlySpan<byte> version)
    {
        string terminated = moduleName.EndsWith(':') ? moduleName : moduleName + ":";
        byte[] name = Encoding.ASCII.GetBytes(terminated);
        int recordLength = 1 + name.Length + 16;
        if (recordLength > ushort.MaxValue)
            throw new ArgumentException("The synthesized .sceversion module name is too long.", nameof(moduleName));
        byte[] record = new byte[recordLength + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(2), (ushort)recordLength);
        record[4] = 8;
        name.CopyTo(record, 5);
        version.CopyTo(record.AsSpan(5 + name.Length, 8));
        version.CopyTo(record.AsSpan(13 + name.Length, 8));
        return record;
    }

    private static ReadOnlySpan<byte> FindElfSection(byte[] elf, string sectionName)
    {
        ulong sectionTableOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(0x28));
        int sectionEntrySize = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x3A));
        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x3C));
        int stringTableIndex = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x3E));
        if (sectionTableOffset == 0 ||
            sectionCount == 0 ||
            sectionEntrySize < SectionHeaderSize ||
            stringTableIndex >= sectionCount ||
            sectionTableOffset > int.MaxValue)
        {
            return ReadOnlySpan<byte>.Empty;
        }
        int tableOffset = (int)sectionTableOffset;
        if (tableOffset + (long)sectionCount * sectionEntrySize > elf.Length)
            throw new ArgumentException("ELF section headers overrun the file.", nameof(elf));

        ReadOnlySpan<byte> stringTable = SectionPayload(elf, tableOffset + stringTableIndex * sectionEntrySize);
        for (int i = 0; i < sectionCount; i++)
        {
            int headerOffset = tableOffset + i * sectionEntrySize;
            uint nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(elf.AsSpan(headerOffset));
            if (nameOffset >= stringTable.Length)
                continue;
            ReadOnlySpan<byte> name = stringTable[(int)nameOffset..];
            int terminator = name.IndexOf((byte)0);
            if (terminator < 0)
                continue;
            if (name[..terminator].SequenceEqual(Encoding.ASCII.GetBytes(sectionName)))
                return SectionPayload(elf, headerOffset);
        }
        return ReadOnlySpan<byte>.Empty;
    }

    private static ReadOnlySpan<byte> SectionPayload(byte[] source, int headerOffset)
    {
        ulong dataOffset = BinaryPrimitives.ReadUInt64LittleEndian(source.AsSpan(headerOffset + 0x18));
        ulong dataSize = BinaryPrimitives.ReadUInt64LittleEndian(source.AsSpan(headerOffset + 0x20));
        if (dataOffset > int.MaxValue || dataSize > int.MaxValue || dataOffset + dataSize > (ulong)source.LongLength)
            throw new ArgumentException("ELF section payload overruns the file.");
        return source.AsSpan((int)dataOffset, (int)dataSize);
    }

    private static ulong DeriveAuthorityId(byte[] elf, ushort eType)
    {
        bool executable = eType is 2 or 0xFE00 or 0xFE10;
        byte exInfo = elf.Length > ExInfoByteOffset ? elf[ExInfoByteOffset] : (byte)0;
        return exInfo switch
        {
            0x40 => executable ? 0x3100000000001101UL : 0x3100000000001102UL,
            0x80 => executable ? 0x3100000000001001UL : 0x3100000000001002UL,
            _ => executable ? 0x3100000000000001UL : 0x3100000000000002UL,
        };
    }

    private static List<SelectedSegment> SelectSegments(byte[] elf, int programHeaderOffset, int programHeaderCount)
    {
        var result = new List<SelectedSegment>(programHeaderCount);
        for (int i = 0; i < programHeaderCount; i++)
        {
            int offset = programHeaderOffset + i * ElfProgramHeaderSize;
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(elf.AsSpan(offset));
            long fileOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(offset + 0x08));
            long fileSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(offset + 0x20));
            if (fileSize <= 0 || fileOffset + fileSize > elf.Length)
                continue;
            if (type is PtLoad or PtModuleData or PtRelro or PtComment)
                result.Add(new SelectedSegment(i, (int)fileOffset, (int)fileSize));
        }
        return result;
    }

    private static void WriteSegment(Span<byte> span, int entry, ulong flags, int offset, long fileSize, long memSize)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(span[entry..], flags);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(entry + 0x08)..], (ulong)offset);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(entry + 0x10)..], (ulong)fileSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[(entry + 0x18)..], (ulong)memSize);
    }

    private static int AlignUp(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);

    private readonly record struct SelectedSegment(int ProgramHeaderIndex, int FileOffset, int FileSize);
}
