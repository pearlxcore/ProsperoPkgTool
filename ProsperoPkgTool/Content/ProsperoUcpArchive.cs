using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ProsperoPkgTool.Content;

/// <summary>
/// Clean-room reader, producer and digest-repair helper for the UCP archive used by the trophy and
/// user-data-system components of a PS5 package (<c>sce_sys/trophy2/*.ucp</c> and
/// <c>sce_sys/uds/*.ucp</c>).
/// </summary>
/// <remarks>
/// Layout (big-endian scalars):
/// <list type="bullet">
/// <item>Header, 0x60 bytes: 0x00 u32 magic <c>0xB228C60A</c>; 0x04 u32 version (1); 0x08 u64 total
/// file size; 0x10 u32 entry count; 0x14 u32 entry-record size (0x40); 0x18 u32 zero; 0x1C 20-byte
/// SHA-1 digest; 0x30..0x60 reserved zero.</item>
/// <item>Entry table at 0x60, one 0x40-byte record per entry: 32-byte NUL-padded name, u64 blob
/// offset, u64 blob size, 16 reserved bytes. Records are ordered by name (ordinal).</item>
/// <item>Blob region: each blob starts at the next 16-byte boundary strictly after the previous
/// blob (a full 16-byte pad when the previous end is already aligned); the file size is padded the
/// same way. The digest is SHA-1 over the whole file with the digest field zeroed.</item>
/// </list>
/// </remarks>
public static class ProsperoUcpArchive
{
    /// <summary>Archive magic (big-endian) at file offset 0x00.</summary>
    public const uint Magic = 0xB228C60A;

    /// <summary>Format version at file offset 0x04.</summary>
    public const uint Version = 1;

    /// <summary>Fixed header size, in bytes.</summary>
    public const int HeaderSize = 0x60;

    /// <summary>Fixed per-entry record size, in bytes.</summary>
    public const int EntryRecordSize = 0x40;

    /// <summary>Fixed name field size inside an entry record, in bytes.</summary>
    public const int NameFieldSize = 0x20;

    private const int DigestOffset = 0x1C;
    private const int DigestSize = 20;
    private const int BlobAlignment = 16;

    /// <summary>One named blob inside a UCP archive.</summary>
    public sealed record Entry(string Name, byte[] Data);

    /// <summary>Returns whether the buffer begins with a UCP header.</summary>
    public static bool IsUcp(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderSize && BinaryPrimitives.ReadUInt32BigEndian(data) == Magic;

    /// <summary>Reads the entry list from a structurally valid UCP archive.</summary>
    /// <exception cref="InvalidDataException">The buffer is not a structurally valid archive.</exception>
    public static IReadOnlyList<Entry> Read(ReadOnlySpan<byte> data)
    {
        if (!Validate(data, out string? error))
            throw new InvalidDataException(error);
        int count = (int)BinaryPrimitives.ReadUInt32BigEndian(data[16..]);
        var entries = new List<Entry>(count);
        for (int i = 0; i < count; i++)
        {
            int record = HeaderSize + i * EntryRecordSize;
            ReadOnlySpan<byte> nameField = data.Slice(record, NameFieldSize);
            int terminator = nameField.IndexOf((byte)0);
            string name = Encoding.Latin1.GetString(terminator < 0 ? nameField : nameField[..terminator]);
            int offset = (int)BinaryPrimitives.ReadUInt64BigEndian(data[(record + 32)..]);
            int size = (int)BinaryPrimitives.ReadUInt64BigEndian(data[(record + 40)..]);
            entries.Add(new Entry(name, data.Slice(offset, size).ToArray()));
        }
        return entries;
    }

    /// <summary>Builds a UCP archive from a set of named blobs (ordered by name).</summary>
    /// <exception cref="ArgumentException">A name is empty, duplicated, or longer than the name field.</exception>
    public static byte[] Build(IEnumerable<Entry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        Entry[] ordered = entries.OrderBy(e => e.Name, StringComparer.Ordinal).ToArray();
        var names = new byte[ordered.Length][];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < ordered.Length; i++)
        {
            string name = ordered[i].Name;
            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("A UCP entry name must not be empty.", nameof(entries));
            byte[] encoded = Encoding.Latin1.GetBytes(name);
            if (encoded.Length > NameFieldSize)
                throw new ArgumentException($"UCP entry name '{name}' exceeds {NameFieldSize} bytes.", nameof(entries));
            if (!seen.Add(name))
                throw new ArgumentException($"Duplicate UCP entry name '{name}'.", nameof(entries));
            names[i] = encoded;
        }

        long cursor = HeaderSize + (long)ordered.Length * EntryRecordSize;
        var offsets = new long[ordered.Length];
        for (int i = 0; i < ordered.Length; i++)
        {
            offsets[i] = cursor;
            cursor = AlignUpStrict(cursor + ordered[i].Data.Length);
        }
        long fileSize = ordered.Length == 0 ? HeaderSize : cursor;

        byte[] buffer = new byte[fileSize];
        Span<byte> span = buffer;
        BinaryPrimitives.WriteUInt32BigEndian(span, Magic);
        BinaryPrimitives.WriteUInt32BigEndian(span[4..], Version);
        BinaryPrimitives.WriteUInt64BigEndian(span[8..], (ulong)fileSize);
        BinaryPrimitives.WriteUInt32BigEndian(span[16..], (uint)ordered.Length);
        BinaryPrimitives.WriteUInt32BigEndian(span[20..], EntryRecordSize);
        for (int i = 0; i < ordered.Length; i++)
        {
            int record = HeaderSize + i * EntryRecordSize;
            names[i].CopyTo(span[record..]);
            BinaryPrimitives.WriteUInt64BigEndian(span[(record + 32)..], (ulong)offsets[i]);
            BinaryPrimitives.WriteUInt64BigEndian(span[(record + 40)..], (ulong)ordered[i].Data.Length);
            ordered[i].Data.CopyTo(span[(int)offsets[i]..]);
        }
        WriteDigest(buffer);
        return buffer;
    }

    /// <summary>Recomputes the stored SHA-1 digest and reports whether it matches.</summary>
    public static bool VerifyDigest(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            return false;
        Span<byte> stored = stackalloc byte[DigestSize];
        data.Slice(DigestOffset, DigestSize).CopyTo(stored);
        byte[] clone = data.ToArray();
        Array.Clear(clone, DigestOffset, DigestSize);
        Span<byte> computed = stackalloc byte[DigestSize];
        SHA1.HashData(clone, computed);
        return computed.SequenceEqual(stored);
    }

    /// <summary>
    /// Returns a copy of the archive with its SHA-1 digest recomputed, correcting a stale or wrong
    /// digest without touching the entry data.
    /// </summary>
    /// <exception cref="InvalidDataException">The buffer is not a UCP archive.</exception>
    public static byte[] WithRepairedDigest(ReadOnlySpan<byte> data)
    {
        if (!IsUcp(data))
            throw new InvalidDataException("Buffer is not a UCP archive.");
        byte[] clone = data.ToArray();
        WriteDigest(clone);
        return clone;
    }

    /// <summary>
    /// Returns the archive unchanged when its digest already verifies, otherwise a repaired copy.
    /// Non-UCP buffers are returned unchanged.
    /// </summary>
    public static byte[] RepairIfNeeded(byte[] data)
    {
        try
        {
            if (IsUcp(data) && !VerifyDigest(data))
                return WithRepairedDigest(data);
        }
        catch (InvalidDataException)
        {
            // A malformed archive is packed unchanged; the repair is best-effort.
        }
        return data;
    }

    /// <summary>
    /// True when a <c>sce_sys</c>-relative path is a trophy2/uds <c>.ucp</c> archive that the
    /// builder repairs in place before it becomes an outer CNT entry.
    /// </summary>
    public static bool IsRepairableSceSysPath(string sceSysRelativePath) =>
        (sceSysRelativePath.StartsWith("trophy2/", StringComparison.Ordinal) ||
         sceSysRelativePath.StartsWith("uds/", StringComparison.Ordinal)) &&
        sceSysRelativePath.EndsWith(".ucp", StringComparison.OrdinalIgnoreCase);

    /// <summary>Validates the header and entry table (not the digest).</summary>
    public static bool Validate(ReadOnlySpan<byte> data, out string? error)
    {
        if (data.Length < HeaderSize)
        {
            error = "Buffer is smaller than a UCP header.";
            return false;
        }
        if (BinaryPrimitives.ReadUInt32BigEndian(data) != Magic)
        {
            error = "Bad UCP magic.";
            return false;
        }
        if (BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != Version)
        {
            error = "Unsupported UCP version.";
            return false;
        }
        ulong size = BinaryPrimitives.ReadUInt64BigEndian(data[8..]);
        if (size != (ulong)data.Length)
        {
            error = $"UCP size field ({size}) does not match buffer length ({data.Length}).";
            return false;
        }
        if (BinaryPrimitives.ReadUInt32BigEndian(data[20..]) != EntryRecordSize)
        {
            error = "Unexpected UCP entry-record size.";
            return false;
        }
        long count = BinaryPrimitives.ReadUInt32BigEndian(data[16..]);
        long tableEnd = HeaderSize + count * EntryRecordSize;
        if (tableEnd > data.Length)
        {
            error = "UCP entry table overruns the buffer.";
            return false;
        }
        for (int i = 0; i < count; i++)
        {
            int record = HeaderSize + i * EntryRecordSize;
            ulong offset = BinaryPrimitives.ReadUInt64BigEndian(data[(record + 32)..]);
            ulong length = BinaryPrimitives.ReadUInt64BigEndian(data[(record + 40)..]);
            if (offset < (ulong)tableEnd || offset + length > size)
            {
                error = $"UCP entry {i} range [{offset},{offset + length}) is outside the blob region.";
                return false;
            }
        }
        error = null;
        return true;
    }

    private static void WriteDigest(byte[] buffer)
    {
        Array.Clear(buffer, DigestOffset, DigestSize);
        Span<byte> digest = stackalloc byte[DigestSize];
        SHA1.HashData(buffer, digest);
        digest.CopyTo(buffer.AsSpan(DigestOffset));
    }

    private static long AlignUpStrict(long value) => (value / BlobAlignment + 1) * BlobAlignment;
}
