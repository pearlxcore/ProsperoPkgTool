using System.Buffers.Binary;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// One supported debug/nwonly PlayGo entity. This is a clean-room semantic model over finalized
/// inner-image leaves; it deliberately does not reproduce publisher node classes or transient flags.
/// </summary>
public sealed record ProsperoPlayGoFileRecord(string Path, byte ChunkId, ulong PathHash);

/// <summary>Creates the single hash-sorted PlayGo population shared by the observed 0x38 and FICM payloads.</summary>
public static class ProsperoPlayGoRecordBuilder
{
    /// <summary>
    /// Enumerates final regular leaves from the assembler snapshot. <paramref name="chunkAssignments"/>
    /// uses normalized inner paths; absent assignments use the scoped debug/nwonly default chunk zero.
    /// Callers that support an explicit assignment vocabulary must pass it here rather than infer it
    /// from FICM or physical layout.
    /// </summary>
    public static IReadOnlyList<ProsperoPlayGoFileRecord> Build(
        ProsperoInnerImageAssembler.InnerImageResult inner,
        IReadOnlyDictionary<string, byte>? chunkAssignments = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        var files = inner.Nodes.Where(n => !n.IsDirectory && n.FullPath.Length != 0).ToList();
        if (files.Count == 0)
            return [];

        var normalizedAssignments = new Dictionary<string, byte>(StringComparer.Ordinal);
        if (chunkAssignments is not null)
        {
            foreach ((string path, byte chunk) in chunkAssignments)
                normalizedAssignments[NormalizePath(path)] = chunk;
        }

        var known = new HashSet<string>(files.Select(f => NormalizePath(f.FullPath)), StringComparer.Ordinal);
        var result = new List<ProsperoPlayGoFileRecord>(files.Count);
        foreach (ProsperoInnerImageAssembler.MetaNodeInfo file in files)
        {
            string path = NormalizePath(file.FullPath);
            // An assignment that names no leaf is stale dump data, not a build error: the leaf keeps
            // the default chunk zero, exactly as if it were absent from the assignment vocabulary.
            byte chunk = normalizedAssignments.TryGetValue(path, out byte value) ? value : (byte)0;
            result.Add(new ProsperoPlayGoFileRecord(path, chunk, ProsperoOuterPfsBuilder.FltPathHash(path)));
        }

        result.Sort((a, b) => a.PathHash.CompareTo(b.PathHash));
        // Duplicate hashes cannot be represented in the hash-sorted table; keep the first occurrence
        // (the population is advisory metadata, so a colliding leaf is dropped, not fatal).
        var unique = new List<ProsperoPlayGoFileRecord>(result.Count);
        foreach (ProsperoPlayGoFileRecord record in result)
        {
            if (unique.Count > 0 && unique[^1].PathHash == record.PathHash)
                continue;
            unique.Add(record);
        }
        return unique;
    }

    /// <summary>
    /// Normalizes an inner path for the PlayGo vocabulary: forward slashes, leading slash removed,
    /// uppercased, with non-ASCII characters replaced by '?'. It never throws for odd dump paths.
    /// </summary>
    public static string NormalizePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string value = path.Replace('\\', '/').TrimStart('/');
        var chars = new List<char>(value.Length);
        foreach (char c in value)
        {
            if (c == '/')
            {
                if (chars.Count > 0 && chars[^1] != '/')
                    chars.Add('/');
                continue;
            }
            char upper = c is >= 'a' and <= 'z' ? (char)(c - ('a' - 'A')) : c;
            chars.Add(upper <= 0x7f ? upper : '?');
        }
        while (chars.Count > 0 && chars[^1] == '/')
            chars.RemoveAt(chars.Count - 1);
        return new string(chars.ToArray());
    }
}

/// <summary>Builds only the observed debug/nwonly 0x38 PlayGo hash-table format.</summary>
public static class ProsperoPlayGoHashTableBuilder
{
    public const int HeaderSize = 0x38;
    public const ulong Seed0 = 0x92CA8AAB26A24F51UL;
    public const ulong Seed1 = 0x09BBB761A41BC44DUL;

    public static byte[] Build(IReadOnlyList<ProsperoPlayGoFileRecord> records)
    {
        ValidateSorted(records);
        byte[] data = new byte[checked(HeaderSize + records.Count * sizeof(ulong))];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), 0x08000000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), HeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x0c), checked((uint)(records.Count * sizeof(ulong))));
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x18), 0x544c467f);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x24), checked((uint)records.Count));
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x28), Seed0);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x30), Seed1);
        for (int i = 0; i < records.Count; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(HeaderSize + i * 8), records[i].PathHash);
        return data;
    }

    internal static void ValidateSorted(IReadOnlyList<ProsperoPlayGoFileRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        for (int i = 1; i < records.Count; i++)
            if (records[i - 1].PathHash >= records[i].PathHash)
                throw new ArgumentException("PlayGo records must be strictly unsigned-hash sorted.", nameof(records));
    }
}

/// <summary>Builds FICM for the same supported debug/nwonly record population as the 0x38 table.</summary>
public static class ProsperoPlayGoFicmBuilder
{
    public static byte[] Build(IReadOnlyList<ProsperoPlayGoFileRecord> records)
    {
        ProsperoPlayGoHashTableBuilder.ValidateSorted(records);
        byte[] data = new byte[checked(0x10 + records.Count * 2)];
        BinaryPrimitives.WriteUInt32LittleEndian(data, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x0c), checked((uint)(records.Count * 2)));
        for (int i = 0; i < records.Count; i++)
        {
            data[0x10 + i * 2] = records[i].ChunkId;
            // byte 1 is zero only for the documented clean-room debug/nwonly subset.
        }
        return data;
    }
}
